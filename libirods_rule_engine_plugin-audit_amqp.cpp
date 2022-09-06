// irods includes
#include <irods/irods_logger.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_server_properties.hpp>

// LIST is #defined in irods/reconstants.hpp
// and is an enum entry in proton/type_id.hpp
#ifdef LIST
#  undef LIST
#endif

// stl includes
#include <cstdint>
#include <version>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <map>
#include <fstream>
#include <mutex>

// boost includes
#include <boost/any.hpp>
#include <boost/config.hpp>
#include <boost/regex.hpp>
#include <boost/exception/all.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/format.hpp>

// proton-cpp includes
#include <proton/connection.hpp>
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/message.hpp>
#include <proton/messaging_handler.hpp>
#include <proton/tracker.hpp>
#include <proton/transport.hpp>
#include <proton/sender.hpp>
#include <proton/session.hpp>

// nlohmann includes
#include <nlohmann/json.hpp>

// fmt includes
#include <fmt/core.h>
#include <fmt/compile.h>

namespace
{

	// NOLINTBEGIN(cert-err58-cpp, cppcoreguidelines-avoid-non-const-global-variables)
	std::string audit_pep_regex_to_match{"audit_.*"};
	std::string audit_amqp_topic{"irods_audit_messages"};
	std::string audit_amqp_location{"localhost:5672"};
	std::string audit_amqp_user;
	std::string audit_amqp_password;
	std::string audit_amqp_options;
	std::string log_path_prefix{"/tmp"};
	bool test_mode = false;
	std::ofstream log_file_ofstream;

	std::mutex audit_plugin_mutex;
	// NOLINTEND(cert-err58-cpp, cppcoreguidelines-avoid-non-const-global-variables)

	const char* const rule_engine_name = "audit_amqp";

	using log_re = irods::experimental::log::rule_engine;

#if __cpp_lib_chrono >= 201907
	// we use millisecond precision in our timestamps, so we want to use a clock
	// that does not implement leap seconds as repeated non-leap seconds, if we can.
	using ts_clock = std::chrono::utc_clock;
#else
	// fallback to system_clock
	using ts_clock = std::chrono::system_clock;
#endif

	BOOST_FORCEINLINE void log_proton_error(const proton::error_condition& err_cond, const std::string& log_message)
	{
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"log_message", log_message},
			{"error_condition::name", err_cond.name()},
			{"error_condition::desc", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	// See qpid-cpp docs
	// https://qpid.apache.org/releases/qpid-proton-0.36.0/proton/cpp/api/simple_send_8cpp-example.html
	class send_handler : public proton::messaging_handler
	{
	  public:
		// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
		send_handler(
			const std::string& _message,
			const std::string& _location,
			const std::string& _topic,
			const std::string& _user,
			const std::string& _password)
			: amqp_location(_location)
			, amqp_topic(_topic)
			, user(_user)
			, password(_password)
			, message(_message)
			, message_sent(false)
		{
		}

		void on_container_start(proton::container& container) override
		{
			proton::connection_options conn_opts;
			if (!user.empty()) {
				conn_opts.user(user);
			}
			if (!password.empty()) {
				conn_opts.password(password);
			}
			container.open_sender(
				fmt::format(FMT_COMPILE("{0:s}/{1:s}"), amqp_location, amqp_topic),
				conn_opts);
		}

		void on_sendable(proton::sender& _sender) override
		{
			if (_sender.credit() && !message_sent) {
				_sender.send(message);
				message_sent = true;
			}
		}

		void on_tracker_accept(proton::tracker& tracker) override
		{
			// we're only sending one message
			// so we don't care about the credit system
			// or tracking confirmed messages
			if (message_sent) {
				tracker.connection().close();
			}
		}

		void on_tracker_reject([[maybe_unused]] proton::tracker& _tracker) override
		{
			// clang-format off
			log_re::error({
				{"rule_engine_plugin", rule_engine_name},
				{"log_message", "AMQP server unexpectedly rejected message"}
			});
			// clang-format on
		}

		void on_transport_error(proton::transport& _transport) override
		{
			log_proton_error(_transport.error(), "Transport error in proton messaging handler");
		}

		void on_connection_error(proton::connection& _connection) override
		{
			log_proton_error(_connection.error(), "Connection error in proton messaging handler");
		}

		void on_session_error(proton::session& _session) override
		{
			log_proton_error(_session.error(), "Session error in proton messaging handler");
		}

		void on_receiver_error(proton::receiver& _receiver) override
		{
			log_proton_error(_receiver.error(), "Receiver error in proton messaging handler");
		}

		void on_sender_error(proton::sender& _sender) override
		{
			log_proton_error(_sender.error(), "Sender error in proton messaging handler");
		}

		void on_error(const proton::error_condition& err_cond) override
		{
			log_proton_error(err_cond, "Unknown error in proton messaging handler");
		}

	  private:
		const std::string& amqp_location;
		const std::string& amqp_topic;
		const std::string& user;
		const std::string& password;
		proton::message message;
		bool message_sent;
	}; // class send_handler

	template <class T>
	BOOST_FORCEINLINE void log_exception(
		const T& exception,
		const std::string& log_message,
		const irods::experimental::log::key_value& context_info)
	{
		// clang-format off
		log_re::info({
			{"rule_engine_plugin", rule_engine_name},
			{"log_message", log_message},
			context_info,
			{"exception", exception.what()},
		});
		// clang-format on
	}

	BOOST_FORCEINLINE void insert_as_string_or_base64(
		nlohmann::json& json_obj,
		const std::string& key,
		const std::string& val,
		const std::uint64_t& time_ms)
	{
		try {
			json_obj[key] = nlohmann::json::parse("\"" + val + "\"");
		}
		catch (const nlohmann::json::exception&) {
			using namespace boost::archive::iterators;
			using b64enc = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;

			// encode into base64 string
			std::string val_b64(b64enc(std::begin(val)), b64enc(std::end(val)));
			val_b64.append((3 - val.length() % 3) % 3, '='); // add padding ='s

			// new key for encoded value
			const std::string key_b64 = key + "_b64";

			json_obj[key_b64] = val_b64;

			// clang-format off
			log_re::debug({
				{"rule_engine_plugin", rule_engine_name},
				{"log_message", "Invalid UTF-8 encountered when adding element to message; added as base64"},
				{"element_original_key", key},
				{"element_key", key_b64},
				{"message_timestamp", std::to_string(time_ms)},
			});
			// clang-format on
		}
	}

	// Insert the key arg into arg_map and storing the number of insertions of arg as the value.
	// The value (number of insertions) is returned.
	BOOST_FORCEINLINE auto insert_arg_into_counter_map(std::map<std::string, int>& arg_map, const std::string& arg)
		-> std::size_t
	{
		auto iter = arg_map.find(arg);
		if (iter == arg_map.end()) {
			arg_map.insert(std::make_pair(arg, 1));
			return 1;
		}
		iter->second = iter->second + 1;
		return iter->second;
	}

	// NOLINTNEXTLINE(readability-function-cognitive-complexity)
	auto get_re_configs(const std::string& _instance_name) -> irods::error
	{
		try {
			const auto& rule_engines = irods::get_server_property<const nlohmann::json&>(
				std::vector<std::string>{irods::KW_CFG_PLUGIN_CONFIGURATION, irods::KW_CFG_PLUGIN_TYPE_RULE_ENGINE});
			for (const auto& rule_engine : rule_engines) {
				const auto& inst_name = rule_engine.at(irods::KW_CFG_INSTANCE_NAME).get_ref<const std::string&>();
				if (inst_name == _instance_name) {
					if (rule_engine.count(irods::KW_CFG_PLUGIN_SPECIFIC_CONFIGURATION) > 0) {
						const auto& plugin_spec_cfg = rule_engine.at(irods::KW_CFG_PLUGIN_SPECIFIC_CONFIGURATION);
						audit_pep_regex_to_match = plugin_spec_cfg.at("pep_regex_to_match").get<std::string>();
						audit_amqp_topic = plugin_spec_cfg.at("amqp_topic").get<std::string>();
						audit_amqp_location = plugin_spec_cfg.at("amqp_location").get<std::string>();

						// amqp_user is optional
						const auto amqp_user_cfg = plugin_spec_cfg.find("amqp_user");
						if (amqp_user_cfg == plugin_spec_cfg.end()) {
							audit_amqp_user.clear();
						}
						else {
							audit_amqp_user = amqp_user_cfg->get<std::string>();
						}

						// amqp_password is optional
						const auto amqp_password_cfg = plugin_spec_cfg.find("amqp_password");
						if (amqp_password_cfg == plugin_spec_cfg.end()) {
							audit_amqp_password.clear();
						}
						else {
							audit_amqp_password = amqp_password_cfg->get<std::string>();
						}

						// amqp_options is optional
						const auto amqp_options_cfg = plugin_spec_cfg.find("amqp_options");
						if (amqp_options_cfg == plugin_spec_cfg.end()) {
							audit_amqp_options.clear();
						}
						else {
							audit_amqp_options = amqp_options_cfg->get<std::string>();
						}

						// look for a test mode setting.  if it doesn't exist just keep test_mode at false.
						// if test_mode = true and log_path_prefix isn't set just leave the default
						const auto test_mode_cfg = plugin_spec_cfg.find("test_mode");
						if (test_mode_cfg != plugin_spec_cfg.end()) {
							const auto& test_mode_str = test_mode_cfg->get_ref<const std::string&>();
							test_mode = boost::iequals(test_mode_str, "true");
							if (test_mode) {
								const auto log_path_prefix_cfg = plugin_spec_cfg.find("log_path_prefix");
								if (log_path_prefix_cfg != plugin_spec_cfg.end()) {
									log_path_prefix = log_path_prefix_cfg->get<std::string>();
								}
							}
						}
					}
					else {
						// clang-format off
						log_re::debug({
							{"rule_engine_plugin", rule_engine_name},
							{"log_message", "Using default plugin configuration"},
							{"instance_name", _instance_name},
						});
						// clang-format on
					}

					return SUCCESS();
				}
			}
		}
		catch (const std::out_of_range& e) {
			return ERROR(KEY_NOT_FOUND, e.what());
		}
		catch (const nlohmann::json::exception& e) {
			return ERROR(SYS_LIBRARY_ERROR, e.what());
		}
		catch (const std::exception& e) {
			return ERROR(SYS_INTERNAL_ERR, e.what());
		}
		catch (...) {
			return ERROR(SYS_UNKNOWN_ERROR, "an unknown error occurred");
		}

		return ERROR(SYS_INVALID_INPUT_PARAM, "failed to find plugin configuration");
	}

	auto start([[maybe_unused]] irods::default_re_ctx& re_ctx, const std::string& _instance_name) -> irods::error
	{
		std::lock_guard<std::mutex> lock(audit_plugin_mutex);

		irods::error ret = get_re_configs(_instance_name);
		if (!ret.ok()) {
			// clang-format off
			log_re::error({
				{"rule_engine_plugin", rule_engine_name},
				{"log_message", "Error loading plugin configuration"},
				{"instance_name", _instance_name},
				{"error_result", ret.result()},
			});
			// clang-format on
		}

		nlohmann::json json_obj;

		char host_name[MAX_NAME_LEN];
		gethostname(host_name, MAX_NAME_LEN);

		std::string msg_str;
		std::string log_file;

		try {
			std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
			json_obj["@timestamp"] = time_ms;
			json_obj["hostname"] = host_name;

			pid_t pid = getpid();
			json_obj["pid"] = pid;

			json_obj["action"] = "START";

			if (test_mode) {
				log_file = str(boost::format("%s/%06i.txt") % log_path_prefix % pid);
				json_obj["log_file"] = log_file;
			}
		}
		catch (const irods::exception& e) {
			log_exception(e, "Caught iRODS exception", {"instance_name", _instance_name});
			return ERROR(e.code(), e.what());
		}
		catch (const nlohmann::json::exception& e) {
			log_exception(e, "Caught nlohmann-json exception", {"instance_name", _instance_name});
			return ERROR(SYS_LIBRARY_ERROR, e.what());
		}
		catch (const std::exception& e) {
			log_exception(e, "Caught exception", {"instance_name", _instance_name});
			return ERROR(SYS_INTERNAL_ERR, e.what());
		}
		catch (...) {
			return ERROR(SYS_UNKNOWN_ERROR, "an unknown error occurred");
		}

		msg_str = json_obj.dump();
		send_handler handler(
			msg_str,
			audit_amqp_location,
			audit_amqp_topic,
			audit_amqp_user,
			audit_amqp_password);
		proton::container(handler).run();

		if (test_mode) {
			log_file_ofstream.open(log_file);
			log_file_ofstream << msg_str << std::endl;
		}

		return SUCCESS();
	}

	auto stop([[maybe_unused]] irods::default_re_ctx& re_ctx, const std::string& _instance_name)
		-> irods::error
	{
		std::lock_guard<std::mutex> lock(audit_plugin_mutex);

		nlohmann::json json_obj;

		std::string msg_str;
		std::string log_file;

		try {
			std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
			json_obj["@timestamp"] = time_ms;

			char host_name[MAX_NAME_LEN];
			gethostname(host_name, MAX_NAME_LEN);
			json_obj["hostname"] = host_name;

			pid_t pid = getpid();
			json_obj["pid"] = pid;

			json_obj["action"] = "STOP";

			if (test_mode) {
				json_obj["log_file"] = str(boost::format("%s/%06i.txt") % log_path_prefix % pid);
			}
		}
		catch (const irods::exception& e) {
			log_exception(e, "Caught iRODS exception", {"instance_name", _instance_name});
			return ERROR(e.code(), e.what());
		}
		catch (const nlohmann::json::exception& e) {
			log_exception(e, "Caught nlohmann-json exception", {"instance_name", _instance_name});
			return ERROR(SYS_LIBRARY_ERROR, e.what());
		}
		catch (const std::exception& e) {
			log_exception(e, "Caught exception", {"instance_name", _instance_name});
			return ERROR(SYS_INTERNAL_ERR, e.what());
		}
		catch (...) {
			return ERROR(SYS_UNKNOWN_ERROR, "an unknown error occurred");
		}

		msg_str = json_obj.dump();
		send_handler handler(
			msg_str,
			audit_amqp_location,
			audit_amqp_topic,
			audit_amqp_user,
			audit_amqp_password);
		proton::container(handler).run();

		if (test_mode) {
			log_file_ofstream << msg_str << std::endl;
			log_file_ofstream.close();
		}

		return SUCCESS();
	}

	auto rule_exists([[maybe_unused]] irods::default_re_ctx& re_ctx, const std::string& _rn, bool& _ret) -> irods::error
	{
		try {
			boost::smatch matches;
			boost::regex expr(audit_pep_regex_to_match);
			_ret = boost::regex_match(_rn, matches, expr);
		}
		catch (const boost::exception& _e) {
			std::string what = boost::diagnostic_information(_e);
			return ERROR(SYS_INTERNAL_ERR, what);
		}

		return SUCCESS();
	}

	auto list_rules([[maybe_unused]] irods::default_re_ctx& re_ctx, [[maybe_unused]] std::vector<std::string>& rules)
		-> irods::error
	{
		return SUCCESS();
	}

	auto exec_rule(
		[[maybe_unused]] irods::default_re_ctx& re_ctx,
		const std::string& _rn,
		std::list<boost::any>& _ps,
		irods::callback _eff_hdlr) -> irods::error
	{
		std::lock_guard<std::mutex> lock(audit_plugin_mutex);

		// stores a counter of unique arg types
		std::map<std::string, int> arg_type_map;

		ruleExecInfo_t* rei = nullptr;
		irods::error err = _eff_hdlr("unsafe_ms_ctx", &rei);
		if (!err.ok()) {
			return err;
		}

		nlohmann::json json_obj;

		std::string msg_str;
		std::string log_file;

		try {
			std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
			json_obj["@timestamp"] = time_ms;

			char host_name[MAX_NAME_LEN];
			gethostname(host_name, MAX_NAME_LEN);
			json_obj["hostname"] = host_name;

			json_obj["pid"] = getpid();
			json_obj["rule_name"] = _rn;

			for (const auto& itr : _ps) {
				// The BytesBuf parameter should not be serialized because this commonly contains
				// the entirety of the contents of files. These could be very big and cause the
				// message broker to explode.
				if (std::type_index(typeid(BytesBuf*)) == std::type_index(itr.type())) {
					// clang-format off
					log_re::trace({
						{"rule_engine_plugin", rule_engine_name},
						{"log_message", "skipping serialization of BytesBuf parameter"},
						{"rule_name", _rn},
					});
					// clang-format on
					continue;
				}

				// serialize the parameter to a map
				irods::re_serialization::serialized_parameter_t param;
				irods::error ret = irods::re_serialization::serialize_parameter(itr, param);
				if (!ret.ok()) {
					// clang-format off
					log_re::error({
						{"rule_engine_plugin", rule_engine_name},
						{"log_message", "failed to serialize argument"},
						{"rule_name", _rn},
						{"error_result", ret.result()},
					});
					// clang-format on
					continue;
				}

				for (const auto& elem : param) {
					std::size_t ctr = insert_arg_into_counter_map(arg_type_map, elem.first);
					std::stringstream ctr_str;
					ctr_str << ctr;

					std::string key = elem.first;
					if (ctr > 1) {
						key += "__";
						key += ctr_str.str();
					}

					insert_as_string_or_base64(json_obj, key, elem.second, time_ms);

					++ctr;
					ctr_str.clear();
				}
			}
		}
		catch (const irods::exception& e) {
			log_exception(e, "Caught iRODS exception", {"rule_name", _rn});
			return ERROR(e.code(), e.what());
		}
		catch (const nlohmann::json::exception& e) {
			log_exception(e, "Caught nlohmann-json exception", {"rule_name", _rn});
			return ERROR(SYS_LIBRARY_ERROR, e.what());
		}
		catch (const std::exception& e) {
			log_exception(e, "Caught exception", {"rule_name", _rn});
			return ERROR(SYS_INTERNAL_ERR, e.what());
		}
		catch (...) {
			return ERROR(SYS_UNKNOWN_ERROR, "an unknown error occurred");
		}

		msg_str = json_obj.dump();
		send_handler handler(
			msg_str,
			audit_amqp_location,
			audit_amqp_topic,
			audit_amqp_user,
			audit_amqp_password);
		proton::container(handler).run();

		if (test_mode) {
			log_file_ofstream << msg_str << std::endl;
		}

		return err;
	}

} // namespace

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C" auto plugin_factory(const std::string& _inst_name, const std::string& _context) -> pluggable_rule_engine*
{
	const auto not_supported = [](auto&&...) { return ERROR(SYS_NOT_SUPPORTED, "Not supported."); };

	auto* rule_engine = new irods::pluggable_rule_engine<irods::default_re_ctx>(_inst_name, _context);

	rule_engine->add_operation("start", std::function<irods::error(irods::default_re_ctx&, const std::string&)>(start));

	rule_engine->add_operation("stop", std::function<irods::error(irods::default_re_ctx&, const std::string&)>(stop));

	rule_engine->add_operation(
		"rule_exists", std::function<irods::error(irods::default_re_ctx&, const std::string&, bool&)>(rule_exists));

	rule_engine->add_operation(
		"list_rules", std::function<irods::error(irods::default_re_ctx&, std::vector<std::string>&)>(list_rules));

	rule_engine->add_operation(
		"exec_rule",
		std::function<irods::error(
			irods::default_re_ctx&, const std::string&, std::list<boost::any>&, irods::callback)>(exec_rule));

	rule_engine->add_operation(
		"exec_rule_text",
		std::function<irods::error(
			irods::default_re_ctx&, const std::string&, msParamArray_t*, const std::string&, irods::callback)>(
			not_supported));

	rule_engine->add_operation(
		"exec_rule_expression",
		std::function<irods::error(irods::default_re_ctx&, const std::string&, msParamArray_t*, irods::callback)>(
			not_supported));

	return rule_engine;
}
