// irods includes
#include <irods/irods_logger.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_server_properties.hpp>

#undef LIST

// stl includes
#include <cstdint>
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
#include <boost/asio/ip/host_name.hpp>
#include <boost/config.hpp>
#include <boost/regex.hpp>
#include <boost/exception/all.hpp>

// proton-cpp includes
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/message.hpp>
#include <proton/messaging_handler.hpp>
#include <proton/tracker.hpp>
#include <proton/sender.hpp>

namespace
{

	// NOLINTBEGIN(cert-err58-cpp, cppcoreguidelines-avoid-non-const-global-variables)
	std::string audit_pep_regex_to_match{"audit_.*"};
	std::string audit_amqp_topic{"irods_audit_messages"};
	std::string audit_amqp_location{"localhost:5672"};
	std::string audit_amqp_user;
	std::string audit_amqp_password;
	std::string audit_amqp_options;

	std::mutex audit_plugin_mutex;
	// NOLINTEND(cert-err58-cpp, cppcoreguidelines-avoid-non-const-global-variables)

	const char* const rule_engine_name = "audit_amqp";

	using log_re = irods::experimental::log::rule_engine;

#if __cpp_lib_chrono >= 201907
	// use utc_clock if it's implemented (for leap seconds)
	using ts_clock = std::chrono::utc_clock;
#else
	// fallback to system_clock
	using ts_clock = std::chrono::system_clock;
#endif

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
			sender = container.open_sender(amqp_location + '/' + amqp_topic, conn_opts);
		}

		void on_tracker_accept(proton::tracker& tracker) override
		{
			// we're only sending one message
			// so we don't care about the credit system
			// or tracking confirmed messages
			tracker.connection().close();
		}

		void on_sendable(proton::sender& _sender) override
		{
			proton::message m(message); // NOLINT(readability-identifier-length)
			m.content_type("application/json");
			_sender.send(m);
		}

	  private:
		const std::string& amqp_location;
		const std::string& amqp_topic;
		const std::string& user;
		const std::string& password;
		const std::string& message;
		proton::sender sender;
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

	BOOST_FORCEINLINE void
	insert_or_parse_as_bin(
		nlohmann::json& json_obj,
		const std::string& key,
		const std::string& val,
		const std::uint64_t& time_ms)
	{
		try {
			json_obj[key] = nlohmann::json::parse("\"" + val + "\"");
		}
		catch (const nlohmann::json::exception&) {
			json_obj[key] = nlohmann::json::binary(std::vector<std::uint8_t>(val.begin(), val.end()));
			// clang-format off
			log_re::debug({
				{"rule_engine_plugin", rule_engine_name},
				{"log_message", "Invalid UTF-8 encountered when adding element to message; added as binary"},
				{"element_key", key},
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

		std::string msg_str;
		std::string log_file;

		try {
			std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
			json_obj["@timestamp"] = time_ms;

			json_obj["hostname"] = boost::asio::ip::host_name();
			json_obj["pid"] = getpid();
			json_obj["action"] = "START";
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

			json_obj["hostname"] = boost::asio::ip::host_name();
			json_obj["pid"] = getpid();
			json_obj["action"] = "STOP";
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

			json_obj["hostname"] = boost::asio::ip::host_name();

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

					insert_or_parse_as_bin(json_obj, key, elem.second, time_ms);

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
