#include "irods/private/audit_amqp.hpp"
#include "irods/private/audit_b64enc.hpp"
#include "irods/private/amqp_config.hpp"
#include "irods/private/amqp_sender.hpp"

#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_error.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_state_table.h>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_structs.hpp>
#include <irods/irods_server_properties.hpp>
#include <irods/msParam.h>
#include <irods/rodsDef.h>
#include <irods/rodsErrorTable.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/any.hpp>
#include <boost/url/url_view.hpp>

#include <fmt/format.h>
#include <fmt/compile.h>

#include <nlohmann/json.hpp>

#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <exception>
#include <iostream>
#include <list>
#include <map>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <version>
#include <utility>

// filesystem
// clang-format off
#ifdef __cpp_lib_filesystem
#include <filesystem>
#include <system_error>
namespace fs = std::filesystem;
using error_code_type = std::error_code;
#else
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
namespace fs = boost::filesystem;
using error_code_type = boost::system::error_code;
#endif
// clang-format on

namespace irods::plugin::rule_engine::audit_amqp
{
	namespace
	{
		const auto pep_regex_flavor = std::regex::ECMAScript;

		// NOLINTBEGIN(cert-err58-cpp, cppcoreguidelines-avoid-non-const-global-variables)
		const std::string_view default_pep_regex_to_match{"pep_.+"};

		const fs::path default_log_path_prefix{fs::temp_directory_path()};
		const bool default_test_mode = false;

		std::string audit_pep_regex_to_match;

		amqp_config audit_amqp_config;

		fs::path log_path_prefix;
		bool test_mode;

		// audit_pep_regex is initially populated with an unoptimized default, as optimization
		// makes construction slower, and we don't expect it to be used before configuration is read.
		std::regex audit_pep_regex{audit_pep_regex_to_match, pep_regex_flavor};

		amqp_sender audit_amqp_sender;

		fs::path log_file_path;
		std::ofstream log_file_ofstream;

		// NOLINTEND(cert-err58-cpp, cppcoreguidelines-avoid-non-const-global-variables)

		void set_default_configs()
		{
			audit_pep_regex_to_match = default_pep_regex_to_match;

			audit_amqp_config.initialize_from_defaults();

			test_mode = default_test_mode;
			log_path_prefix = default_log_path_prefix;

			audit_pep_regex = std::regex(audit_pep_regex_to_match, pep_regex_flavor | std::regex::optimize);
		}

		irods::error get_re_configs(const std::string& _instance_name)
		{
			try {
				const auto& rule_engines = irods::get_server_property<const nlohmann::json&>(std::vector<std::string>{
					irods::KW_CFG_PLUGIN_CONFIGURATION, irods::KW_CFG_PLUGIN_TYPE_RULE_ENGINE});
				for (const auto& rule_engine : rule_engines) {
					const auto& inst_name = rule_engine.at(irods::KW_CFG_INSTANCE_NAME).get_ref<const std::string&>();
					if (inst_name != _instance_name) {
						continue;
					}

					const auto plugin_spec_cfg_ = rule_engine.find(irods::KW_CFG_PLUGIN_SPECIFIC_CONFIGURATION);
					if (plugin_spec_cfg_ == rule_engine.end()) {
						set_default_configs();
						// clang-format off
						log_re::warn({
							{"rule_engine_plugin", rule_engine_name},
							{"instance_name", _instance_name},
							{"log_message", "Using default plugin configuration"},
						});
						// clang-format on

						return SUCCESS();
					}

					const auto& plugin_spec_cfg = *plugin_spec_cfg_;

					audit_pep_regex_to_match = plugin_spec_cfg.at("pep_regex_to_match").get<std::string>();

					irods::error res = audit_amqp_config.initialize(plugin_spec_cfg, _instance_name);
					if (!res.ok()) {
						return PASS(res);
					}

					// test_mode is optional
					const auto test_mode_cfg = plugin_spec_cfg.find("test_mode");
					if (test_mode_cfg == plugin_spec_cfg.end()) {
						test_mode = default_test_mode;
					}
					else if (test_mode_cfg->is_string()) {
						const auto& test_mode_str = test_mode_cfg->get_ref<const std::string&>();
						test_mode = boost::iequals(test_mode_str, "true");
					}
					else {
						test_mode = test_mode_cfg->get<bool>();
					}

					// log_path_prefix is optional
					const auto log_path_prefix_cfg = plugin_spec_cfg.find("log_path_prefix");
					if (log_path_prefix_cfg == plugin_spec_cfg.end()) {
						log_path_prefix = default_log_path_prefix;
					}
					else {
						log_path_prefix = log_path_prefix_cfg->get<std::string>();
					}

					// look for amqp_options and log a warning if it is present
					const auto amqp_options_cfg = plugin_spec_cfg.find("amqp_options");
					if (amqp_options_cfg != plugin_spec_cfg.end()) {
						// clang-format off
						log_re::warn({
							{"rule_engine_plugin", rule_engine_name},
							{"instance_name", _instance_name},
							{"log_message", "Found amqp_options configuration setting. This setting is no longer used "
							                "and should be removed from the plugin configuration."},
						});
						// clang-format on
					}

					audit_pep_regex = std::regex(audit_pep_regex_to_match, pep_regex_flavor | std::regex::optimize);

					return SUCCESS();
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
				return ERROR(SYS_UNKNOWN_ERROR, "An unknown error occurred");
			}

			return ERROR(CONFIGURATION_ERROR, "Failed to find plugin configuration");
		}

		template <class Logger>
		void log_test_mode_diag(const Logger& _logger,
		                        const std::string& _log_message,
		                        const std::string& _instance_name,
		                        const std::string& _test_mode_log_path)
		{
			// clang-format off
			_logger({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_file_path", _test_mode_log_path},
				{"log_message", _log_message},
			});
			// clang-format on
		}

		template <class Logger>
		void log_test_mode_diag(const Logger& _logger,
		                        const std::string& _log_message,
		                        const std::string& _instance_name)
		{
			// clang-format off
			_logger({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_message", _log_message},
			});
			// clang-format on
		}

	} // namespace

	static irods::error setup([[maybe_unused]] irods::default_re_ctx& _re_ctx, const std::string& _instance_name)
	{
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::debug({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _instance_name},
			{"log_message", "setup called"},
		});
		// clang-format on
#endif
		// test log should never throw exceptions
		log_file_ofstream.exceptions(static_cast<std::ios_base::iostate>(0));

		irods::error ret = get_re_configs(_instance_name);
		if (!ret.ok()) {
			// clang-format off
			log_re::error({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_message", "Error loading plugin configuration"},
				{"error_result", ret.result()},
			});
			// clang-format on

			return PASSMSG("Error loading plugin configuration", ret);
		}

		ret = audit_amqp_sender.configure(_instance_name, audit_amqp_config);
		if (!ret.ok()) {
			// clang-format off
			log_re::error({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_message", "Error establishing AMQP connection"},
				{"error_result", ret.result()},
			});
			// clang-format on

			return PASSMSG("Error configuring amqp_sender", ret);
		}

		return SUCCESS();
	} // setup

	static irods::error teardown([[maybe_unused]] irods::default_re_ctx& _re_ctx,
	                             [[maybe_unused]] const std::string& _instance_name)
	{
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::debug({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _instance_name},
			{"log_message", "teardown called"},
		});
		// clang-format on
#endif
		return SUCCESS();
	} // teardown

	static irods::error start([[maybe_unused]] irods::default_re_ctx& _re_ctx, const std::string& _instance_name)
	{
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::debug({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _instance_name},
			{"log_message", "start called"},
		});
		// clang-format on
#endif

		nlohmann::json json_obj;
		const pid_t pid = getpid();

		try {
			const std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);

			irods::error ret = audit_amqp_sender.open();
			if (!ret.ok()) {
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _instance_name},
					{"log_message", "Error establishing AMQP connection"},
					{"error_result", ret.result()},
				});
				// clang-format on

				return PASSMSG("Error establishing AMQP connection", ret);
			}

			json_obj["action"] = "START";

			if (test_mode) {
				if (log_path_prefix.empty()) {
					log_test_mode_diag(
						log_re::trace, "log_path_prefix is empty. cannot open test log.", _instance_name);
					log_file_path.clear();
					// ensure log_file_ofstream is closed
					if (log_file_ofstream.is_open()) {
						log_test_mode_diag(log_re::trace, "log_file_ofstream open. Closing.", _instance_name);
						log_file_ofstream.close();
						if (!log_file_ofstream.good()) {
							log_test_mode_diag(log_re::error, "Error closing log_file_ofstream.", _instance_name);
						}
					}
				}
				else {
					log_file_path = log_path_prefix / fmt::format(FMT_COMPILE("{0:08d}.txt"), pid);
					json_obj["log_file"] = log_file_path;

					const std::string log_file_path_str = log_file_path.string();

					if (log_file_ofstream.is_open()) {
						log_test_mode_diag(log_re::trace,
						                   "log_file_ofstream already open. Closing.",
						                   _instance_name,
						                   log_file_path_str);
						log_file_ofstream.close();
						if (!log_file_ofstream.good()) {
							log_test_mode_diag(log_re::error, "Error closing log_file_ofstream.", _instance_name);
						}
					}

					error_code_type mkdirs_ec;
					fs::create_directories(log_file_path.parent_path(), mkdirs_ec);

					log_test_mode_diag(log_re::trace, "opening log_file_ofstream.", _instance_name, log_file_path_str);
					log_file_ofstream.open(log_file_path, std::ios_base::out | std::ios_base::ate);
					if (!log_file_ofstream.good()) {
						log_test_mode_diag(
							log_re::error, "Error opening log_file_ofstream.", _instance_name, log_file_path_str);
					}
				}
			}
			else {
				// ensure log_file_ofstream is closed
				if (log_file_ofstream.is_open()) {
					log_test_mode_diag(
						log_re::error, "Test mode disabled but log_file_ofstream open. Closing.", _instance_name);
					log_file_ofstream.close();
					if (!log_file_ofstream.good()) {
						log_test_mode_diag(log_re::error, "Error closing log_file_ofstream.", _instance_name);
					}
				}
			}

			audit_amqp_sender.send_message(json_obj, time_ms, pid, log_file_ofstream);
		}
		catch (const irods::exception& e) {
			const std::string e_what = e.what();
			log_exception(log_re::info, "Caught iRODS exception", e_what, _instance_name);
			return ERROR(e.code(), e_what);
		}
		catch (const nlohmann::json::exception& e) {
			const std::string e_what = e.what();
			log_exception(log_re::info, "Caught nlohmann-json exception", e_what, _instance_name);
			return ERROR(SYS_LIBRARY_ERROR, e_what);
		}
		catch (const std::exception& e) {
			const std::string e_what = e.what();
			log_exception(log_re::info, "Caught exception", e_what, _instance_name);
			return ERROR(SYS_INTERNAL_ERR, e_what);
		}
		catch (...) {
			// clang-format off
			log_re::info({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_message", "Caught unknown exception"}
			});
			// clang-format on
			return ERROR(SYS_UNKNOWN_ERROR, "An unknown error occurred");
		}

		return SUCCESS();
	}

	static auto stop([[maybe_unused]] irods::default_re_ctx& _re_ctx, const std::string& _instance_name) -> irods::error
	{
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::debug({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _instance_name},
			{"log_message", "stop called"},
		});
		// clang-format on
#endif

		nlohmann::json json_obj;

		try {
			const std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);

			json_obj["action"] = "STOP";
			if (test_mode && !log_file_path.empty()) {
				json_obj["log_file"] = log_file_path;
			}

			audit_amqp_sender.send_message(json_obj, time_ms, getpid(), log_file_ofstream);
			audit_amqp_sender.close();
		}
		catch (const irods::exception& e) {
			const std::string e_what = e.what();
			log_exception(log_re::info, "Caught iRODS exception", e_what, _instance_name);
			return ERROR(e.code(), e_what);
		}
		catch (const nlohmann::json::exception& e) {
			const std::string e_what = e.what();
			log_exception(log_re::info, "Caught nlohmann-json exception", e_what, _instance_name);
			return ERROR(SYS_LIBRARY_ERROR, e_what);
		}
		catch (const std::exception& e) {
			const std::string e_what = e.what();
			log_exception(log_re::info, "Caught exception", e_what, _instance_name);
			return ERROR(SYS_INTERNAL_ERR, e_what);
		}
		catch (...) {
			// clang-format off
			log_re::info({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_message", "Caught unknown exception"}
			});
			// clang-format on
			return ERROR(SYS_UNKNOWN_ERROR, "An unknown error occurred");
		}

		log_file_ofstream.close();
		if (!log_file_ofstream.good()) {
			// clang-format off
			log_re::error({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"log_message", "Error closing log_file_ofstream."}
			});
			// clang-format on
		}

		return SUCCESS();
	}

	static auto rule_exists([[maybe_unused]] irods::default_re_ctx& _re_ctx, const std::string& _rn, bool& _ret)
		-> irods::error
	{
		try {
			std::smatch matches;
			_ret = std::regex_match(_rn, matches, audit_pep_regex);
		}
		catch (const std::exception& _e) {
			return ERROR(SYS_INTERNAL_ERR, _e.what());
		}
		catch (...) {
			return ERROR(SYS_UNKNOWN_ERROR, "An unknown error occurred");
		}

		return SUCCESS();
	}

	static auto list_rules(
		[[maybe_unused]] irods::default_re_ctx& _re_ctx,
		[[maybe_unused]] std::vector<std::string>& _rules) -> irods::error
	{
		return SUCCESS();
	}

	static auto exec_rule(
		[[maybe_unused]] irods::default_re_ctx& _re_ctx,
		const std::string& _rn,
		std::list<boost::any>& _ps,
		irods::callback _eff_hdlr) -> irods::error
	{
		const std::string& _instance_name = audit_amqp_sender.re_instance_name();

#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::debug({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _instance_name},
			{"log_message", "exec_rule called"},
		});
		// clang-format on
#endif

		// stores a counter of unique arg types
		std::map<std::string, std::size_t> arg_type_map;

		ruleExecInfo_t* rei = nullptr;
		if (const auto err = _eff_hdlr("unsafe_ms_ctx", &rei); !err.ok()) {
			// clang-format off
			log_re::trace({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"rule_name", _rn},
				{"log_message", "Could not get rule execution context (REI)"},
				{"error_result", err.result()}
			});
			// clang-format on
			return CODE(RULE_ENGINE_CONTINUE);
		}

		nlohmann::json json_obj;

		try {
			const std::uint64_t time_ms = ts_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
			json_obj["rule_name"] = _rn;

			for (const auto& itr : _ps) {
				// The BytesBuf parameter should not be serialized because this commonly contains
				// the entirety of the contents of files. These could be very big and cause the
				// message broker to explode.
				if (std::type_index(typeid(BytesBuf*)) == std::type_index(itr.type())) {
					// clang-format off
					log_re::trace({
						{"rule_engine_plugin", rule_engine_name},
						{"instance_name", _instance_name},
						{"rule_name", _rn},
						{"log_message", "Skipping serialization of BytesBuf parameter"}
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
						{"instance_name", _instance_name},
						{"rule_name", _rn},
						{"log_message", "Failed to serialize argument"},
						{"error_result", ret.result()}
					});
					// clang-format on
					continue;
				}

				for (const auto& elem : param) {
					const std::string& arg = elem.first;

					std::size_t ctr;
					const auto iter = arg_type_map.find(arg);
					if (iter == arg_type_map.end()) {
						arg_type_map.insert(std::make_pair(arg, static_cast<std::size_t>(1)));
						ctr = 1;
					}
					else {
						ctr = iter->second + 1;
						iter->second = ctr;
					}

					if (ctr > 1) {
						const std::string key = fmt::format(FMT_COMPILE("{0:s}__{1:d}"), arg, ctr);
						insert_as_string_or_base64(json_obj, key, elem.second, time_ms);
					}
					else {
						insert_as_string_or_base64(json_obj, arg, elem.second, time_ms);
					}
				}
			}

			audit_amqp_sender.send_message(json_obj, time_ms, getpid(), log_file_ofstream);
		}
		catch (const irods::exception& e) {
			log_exception(log_re::info, "Caught iRODS exception", e.what(), _instance_name, _rn);
		}
		catch (const nlohmann::json::exception& e) {
			log_exception(log_re::info, "Caught nlohmann-json exception", e.what(), _instance_name, _rn);
		}
		catch (const std::exception& e) {
			log_exception(log_re::info, "Caught exception", e.what(), _instance_name, _rn);
		}
		catch (...) {
			// clang-format off
			log_re::info({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _instance_name},
				{"rule_name", _rn},
				{"log_message", "Caught unknown exception"}
			});
			// clang-format on
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}
} // namespace irods::plugin::rule_engine::audit_amqp

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C" auto plugin_factory(const std::string& _inst_name, const std::string& _context) -> pluggable_rule_engine*
{
	using namespace irods::plugin::rule_engine::audit_amqp;

	set_default_configs();

	const auto not_supported = [](auto&&...) { return ERROR(SYS_NOT_SUPPORTED, "Not supported."); };

	auto* rule_engine = new irods::pluggable_rule_engine<irods::default_re_ctx>(_inst_name, _context);

	rule_engine->add_operation("setup", std::function{setup});
	rule_engine->add_operation("teardown", std::function{teardown});

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
