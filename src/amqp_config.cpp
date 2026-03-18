#include "irods/private/audit_amqp.hpp"
#include "irods/private/amqp_config.hpp"

#include <irods/irods_error.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/url/url_view.hpp>

#include <nlohmann/json.hpp>

#include <proton/target.hpp>

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>

namespace irods::plugin::rule_engine::audit_amqp
{
	irods::error amqp_config::initialize(const nlohmann::json& _plugin_specific_configuration,
	                                     const std::string& _re_instance_name)
	{
		// start fresh
		deinitialize();

		bool found_endpoint = false;
		const auto amqp_endpoints_cfg = _plugin_specific_configuration.find("amqp_endpoints");
		if (amqp_endpoints_cfg != _plugin_specific_configuration.end()) {
			const auto& endpoints_cfg = *amqp_endpoints_cfg;
			for (const auto& endpoint_cfg : endpoints_cfg) {
				std::stringstream endpoint_ss;

				const auto scheme_cfg = endpoint_cfg.find("scheme");
				if (scheme_cfg != endpoint_cfg.end()) {
					endpoint_ss << scheme_cfg->get_ref<const std::string&>() << "://";
				}

				const auto& host = endpoint_cfg.at("host").get_ref<const std::string&>();
				endpoint_ss << host;

				const auto port_cfg = endpoint_cfg.find("port");
				if (port_cfg != endpoint_cfg.end()) {
					const auto& port = port_cfg->get_ref<const nlohmann::json::number_unsigned_t&>();
					if (port > std::numeric_limits<std::uint16_t>::max()) {
						// clang-format off
						log_re::error({
							{"rule_engine_plugin", rule_engine_name},
							{"instance_name", _re_instance_name},
							{"log_message", "AMQP endpoint port must not exceed 65535."},
							{"port", std::to_string(port)}
						});
						// clang-format on
						return ERROR(CONFIGURATION_ERROR, "AMQP endpoint port greater than 65535.");
					}
					endpoint_ss << ':' << std::to_string(port);
				}

				bool found_endpoint_params = false;
				const auto endpoint_params_cfg = endpoint_cfg.find("parameters");
				if (endpoint_params_cfg != endpoint_cfg.end()) {
					const auto& endpoint_params = *endpoint_params_cfg;
					for (const auto& [ep_key, ep_val] : endpoint_params.items()) {
						if (found_endpoint_params) {
							endpoint_ss << '&' << ep_key;
						}
						else {
							endpoint_ss << "/?" << ep_key;
						}

						found_endpoint_params = true;

						if (ep_val.is_null()) {
							continue;
						}

						endpoint_ss << '=' << ep_val.get_ref<const std::string&>();
					}
				}

				const auto endpoint_frag_cfg = endpoint_cfg.find("fragment");
				if (endpoint_frag_cfg != endpoint_cfg.end()) {
					const auto& endpoint_frag = *endpoint_frag_cfg;
					endpoint_ss << '#';
					if (!endpoint_frag.is_null()) {
						endpoint_ss << endpoint_frag.get_ref<const std::string&>();
					}
				}

				if (found_endpoint) {
					failover_endpoints_.push_back(endpoint_ss.str());
				}
				else {
					primary_endpoint_ = endpoint_ss.str();
					found_endpoint = true;
				}
			}
		}

		bool found_user = false;
		const auto user_cfg = _plugin_specific_configuration.find("amqp_user");
		if (user_cfg == _plugin_specific_configuration.end()) {
			user_ = defaults::user;
		}
		else {
			user_ = user_cfg->get_ref<const std::string&>();
			found_user = true;
		}

		bool found_password = false;
		const auto password_cfg = _plugin_specific_configuration.find("amqp_password");
		if (password_cfg == _plugin_specific_configuration.end()) {
			password_ = defaults::password;
		}
		else {
			password_ = password_cfg->get_ref<const std::string&>();
			found_password = true;
		}

		// check amqp_location
		const auto amqp_location_cfg = _plugin_specific_configuration.find("amqp_location");
		if (amqp_location_cfg == _plugin_specific_configuration.end()) {
			if (!found_endpoint) {
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _re_instance_name},
					{"log_message", "amqp_endpoints empty or not present in rule engine configuration."}
				});
				// clang-format on
				return ERROR(CONFIGURATION_ERROR, "amqp_endpoints empty or not present in rule engine configuration.");
			}
		}
		else {
			// clang-format off
			log_re::warn({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _re_instance_name},
				{"log_message", "Found amqp_location configuration setting. This setting has been deprecated in favor "
				                "of amqp_endpoints, amqp_user, and amqp_password and will be ignored in future "
				                "versions of the plugin."}
			});
			// clang-format on

			const auto& amqp_location = amqp_location_cfg->get_ref<const std::string&>();
			const boost::urls::url_view proton_url(amqp_location);

			if (found_endpoint) {
				// clang-format off
				log_re::info({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _re_instance_name},
					{"log_message", "Ignoring location from amqp_location in favor of amqp_endpoints."},
				});
				// clang-format on
			}
			else {
				if (!proton_url.has_authority()) {
					// clang-format off
					log_re::error({
						{"rule_engine_plugin", rule_engine_name},
						{"instance_name", _re_instance_name},
						{"log_message", "Could not get host from amqp_location"},
						{"amqp_location", amqp_location},
					});
					// clang-format on
					return ERROR(CONFIGURATION_ERROR, "Cannot derive AMQP endpoint host from amqp_location.");
				}

				std::stringstream endpoint_ss;
				if (proton_url.has_scheme()) {
					endpoint_ss << proton_url.scheme() << "://";
				}
				endpoint_ss << proton_url.encoded_host_and_port();

				if (proton_url.has_query() || proton_url.has_fragment()) {
					endpoint_ss << '/';
					if (proton_url.has_query()) {
						endpoint_ss << '?' << proton_url.encoded_query();
					}
					if (proton_url.has_fragment()) {
						endpoint_ss << '#' << proton_url.encoded_fragment();
					}
				}

				primary_endpoint_ = endpoint_ss.str();
			}

			if (proton_url.has_userinfo()) {
				if (found_user) {
					// clang-format off
					log_re::info({
						{"rule_engine_plugin", rule_engine_name},
						{"instance_name", _re_instance_name},
						{"log_message", "Ignoring credentials from amqp_location in favor of amqp_user and "
						                "amqp_password."},
					});
					// clang-format on
				}
				else {
					user_ = proton_url.user();
					if (proton_url.has_password()) {
						if (found_password) {
							// clang-format off
							log_re::info({
								{"rule_engine_plugin", rule_engine_name},
								{"instance_name", _re_instance_name},
								{"log_message", "Ignoring password from amqp_location in favor of amqp_password."},
							});
							// clang-format on
						}
						else {
							password_ = proton_url.password();
						}
					}
				}
			}
		}

		failover_endpoints_.shrink_to_fit();

		bool found_path = false;
		std::stringstream path_ss;
		const auto amqp_path_cfg = _plugin_specific_configuration.find("amqp_path");
		if (amqp_path_cfg != _plugin_specific_configuration.end()) {
			const auto& amqp_path_str = amqp_path_cfg->get_ref<const std::string&>();
			if (!amqp_path_str.empty()) {
				path_ss << '/' << amqp_path_str;
			}
			found_path = true;
		}

		// check amqp_topic
		const auto amqp_topic_cfg = _plugin_specific_configuration.find("amqp_topic");
		if (amqp_topic_cfg == _plugin_specific_configuration.end()) {
			if (!found_path) {
				// clang-format off
				log_re::info({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _re_instance_name},
					{"log_message", "amqp_path not present in rule engine configuration."}
				});
				// clang-format on
			}
		}
		else {
			// clang-format off
			log_re::warn({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _re_instance_name},
				{"log_message", "Found amqp_topic configuration setting. This setting has been deprecated in favor of "
				                "amqp_path and will be ignored in future versions of the plugin."}
			});
			// clang-format on

			if (found_path) {
				// clang-format off
				log_re::info({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _re_instance_name},
					{"log_message", "Ignoring amqp_topic in favor of amqp_path."},
				});
				// clang-format on
			}
			else {
				const auto& amqp_topic_str = amqp_topic_cfg->get_ref<const std::string&>();
				if (!amqp_topic_str.empty()) {
					path_ss << '/' << amqp_topic_str;
				}
			}
		}

		bool found_path_params = false;
		const auto path_params_cfg = _plugin_specific_configuration.find("amqp_path_parameters");
		if (path_params_cfg != _plugin_specific_configuration.end()) {
			const auto& path_params = *path_params_cfg;
			for (const auto& [pp_key, pp_val] : path_params.items()) {
				path_ss << (found_path_params ? '&' : '?') << pp_key;

				found_path_params = true;

				if (pp_val.is_null()) {
					continue;
				}

				path_ss << '=' << pp_val.get_ref<const std::string&>();
			}
		}

		const auto path_frag_cfg = _plugin_specific_configuration.find("amqp_path_fragment");
		if (path_frag_cfg != _plugin_specific_configuration.end()) {
			const auto& path_frag = *path_frag_cfg;
			path_ss << '#';
			if (!path_frag.is_null()) {
				path_ss << path_frag.get_ref<const std::string&>();
			}
		}

		path_ = path_ss.str();

		const auto amqp_sasl_cfg = _plugin_specific_configuration.find("amqp_sasl");
		if (amqp_sasl_cfg == _plugin_specific_configuration.end()) {
			sasl_enabled_ = defaults::sasl_enabled;
			sasl_mechanisms_ = defaults::sasl_mechanisms;
			sasl_allow_insecure_ = defaults::sasl_allow_insecure;
		}
		else {
			const auto& sasl_cfg = *amqp_sasl_cfg;

			const auto sasl_enabled_cfg = sasl_cfg.find("enable");
			if (sasl_enabled_cfg == sasl_cfg.end()) {
				sasl_enabled_ = defaults::sasl_enabled;
			}
			else {
				sasl_enabled_ = sasl_enabled_cfg->get<bool>();
			}

			const auto mechanisms_cfg = sasl_cfg.find("mechanisms");
			if (mechanisms_cfg == sasl_cfg.end()) {
				sasl_mechanisms_ = defaults::sasl_mechanisms;
			}
			else if (mechanisms_cfg->is_array()) {
				const auto& mechanisms_arr = mechanisms_cfg->get_ref<const nlohmann::json::array_t&>();
				if (mechanisms_arr.empty()) {
					sasl_mechanisms_ = "";
				}
				auto mechanisms_itr = mechanisms_arr.begin();
				std::stringstream mechanisms_ss;
				mechanisms_ss << mechanisms_itr->get_ref<const std::string&>();
				while (++mechanisms_itr != mechanisms_arr.end()) {
					mechanisms_ss << ' ' << mechanisms_itr->get_ref<const std::string&>();
				}
				sasl_mechanisms_ = mechanisms_ss.str();
			}
			else {
				sasl_mechanisms_ = mechanisms_cfg->get_ref<const std::string&>();
			}

			const auto sasl_allow_insecure_cfg = sasl_cfg.find("allow_insecure");
			if (sasl_allow_insecure_cfg == sasl_cfg.end()) {
				sasl_allow_insecure_ = defaults::sasl_allow_insecure;
			}
			else {
				sasl_allow_insecure_ = sasl_allow_insecure_cfg->get<bool>();
			}
		}

		const auto sender_durability_cfg = _plugin_specific_configuration.find("amqp_sender_durability_mode");
		if (sender_durability_cfg == _plugin_specific_configuration.end()) {
			sender_durability_mode_ = defaults::sender_durability_mode;
		}
		else {
			const std::string& sender_durability_string = sender_durability_cfg->get_ref<const std::string&>();

			if (sender_durability_string == "NONDURABLE") {
				sender_durability_mode_ = proton::target::durability_mode::NONDURABLE;
			}
			else if (sender_durability_string == "CONFIGURATION") {
				sender_durability_mode_ = proton::target::durability_mode::CONFIGURATION;
			}
			else if (sender_durability_string == "UNSETTLED_STATE") {
				sender_durability_mode_ = proton::target::durability_mode::UNSETTLED_STATE;
			}
			else {
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _re_instance_name},
					{"log_message", "amqp_sender_durability_mode must be one of "
					                "[NONDURABLE, CONFIGURATION, UNSETTLED_STATE]."},
					{"durability_mode", sender_durability_string}
				});
				// clang-format on
				return ERROR(CONFIGURATION_ERROR, "Unrecognized amqp_sender_durability_mode value.");
			}
		}

		const auto amqp_durable_messages_cfg = _plugin_specific_configuration.find("amqp_durable_messages");
		if (amqp_durable_messages_cfg == _plugin_specific_configuration.end()) {
			durable_messages_ = defaults::durable_messages;
		}
		else if (amqp_durable_messages_cfg->is_string()) {
			const auto& amqp_durable_messages_str = amqp_durable_messages_cfg->get_ref<const std::string&>();
			durable_messages_ = boost::iequals(amqp_durable_messages_str, "true");
		}
		else {
			durable_messages_ = amqp_durable_messages_cfg->get<bool>();
		}

		is_initialized_ = true;
		return SUCCESS();
	}
} //namespace irods::plugin::rule_engine::audit_amqp
