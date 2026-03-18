#ifndef IRODS_AUDIT_AUDIT_CONFIG_HPP
#define IRODS_AUDIT_AUDIT_CONFIG_HPP

#include "irods/private/audit_amqp.hpp"

#include <irods/irods_error.hpp>

#include <nlohmann/json.hpp>

#include <proton/target.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace irods::plugin::rule_engine::audit_amqp
{
	class amqp_config
	{
	  public:
		class defaults
		{
		  public:
			defaults() = delete;

			static constexpr const std::string_view primary_endpoint{"amqp://localhost:5672"};

			static constexpr const std::string_view path{"queues/irods_audit_messages"};

			static constexpr const std::string_view user{};
			static constexpr const std::string_view password{};

			static constexpr const std::optional<bool> sasl_enabled = std::nullopt;
			static constexpr const std::optional<std::string> sasl_mechanisms = std::nullopt;
			static constexpr const std::optional<bool> sasl_allow_insecure = std::nullopt;

			static constexpr const enum proton::target::durability_mode sender_durability_mode =
				proton::target::durability_mode::UNSETTLED_STATE;

			static constexpr const bool durable_messages = true;
		};

		irods::error initialize(const nlohmann::json& _plugin_specific_configuration,
		                        const std::string& _re_instance_name);

		void deinitialize()
		{
			is_initialized_ = false;

			primary_endpoint_.clear();
			failover_endpoints_.clear();

			path_.clear();

			user_.clear();
			password_.clear();

			sasl_enabled_ = std::nullopt;
			sasl_mechanisms_ = std::nullopt;
			sasl_allow_insecure_ = std::nullopt;

			sender_durability_mode_ = std::nullopt;

			durable_messages_ = std::nullopt;
		}

		void initialize_from_defaults()
		{
			primary_endpoint_ = defaults::primary_endpoint;
			failover_endpoints_.clear();
			failover_endpoints_.shrink_to_fit();

			path_ = defaults::path;

			user_ = defaults::user;
			password_ = defaults::password;

			sasl_enabled_ = defaults::sasl_enabled;
			sasl_mechanisms_ = defaults::sasl_mechanisms;
			sasl_allow_insecure_ = defaults::sasl_allow_insecure;

			sender_durability_mode_ = defaults::sender_durability_mode;

			durable_messages_ = defaults::durable_messages;

			is_initialized_ = true;
		}

		[[nodiscard]] constexpr bool is_initialized() const { return is_initialized_; }

		[[nodiscard]] constexpr const std::string& primary_endpoint() const { return primary_endpoint_; }
		[[nodiscard]] constexpr const std::vector<std::string>& failover_endpoints() const { return failover_endpoints_; }
		[[nodiscard]] constexpr const std::string& path() const { return path_; }
		[[nodiscard]] constexpr const std::string& user() const { return user_; }
		[[nodiscard]] constexpr const std::string& password() const { return password_; }
		[[nodiscard]] constexpr const std::optional<bool>& sasl_enabled() const { return sasl_enabled_; }
		[[nodiscard]] constexpr const std::optional<std::string>& sasl_mechanisms() const { return sasl_mechanisms_; }
		[[nodiscard]] constexpr const std::optional<bool>& sasl_allow_insecure() const { return sasl_allow_insecure_; }
		[[nodiscard]] constexpr const std::optional<enum proton::target::durability_mode>& sender_durability_mode() const { return sender_durability_mode_; }
		[[nodiscard]] constexpr const std::optional<bool>& durable_messages() const { return durable_messages_; }

		static const amqp_config& default_config()
		{
			if (!default_instance_.has_value()) {
				amqp_config config;
				config.initialize_from_defaults();
				default_instance_ = config;
			}

			return *default_instance_;
		}

	  private:
		bool is_initialized_{false};

		std::string primary_endpoint_;
		std::vector<std::string> failover_endpoints_;

		std::string path_;

		std::string user_;
		std::string password_;

		std::optional<bool> sasl_enabled_;
		std::optional<std::string> sasl_mechanisms_;
		std::optional<bool> sasl_allow_insecure_;

		std::optional<enum proton::target::durability_mode> sender_durability_mode_;

		std::optional<bool> durable_messages_;

		static std::optional<amqp_config> default_instance_;
	};
} //namespace irods::plugin::rule_engine::audit_amqp

#endif // IRODS_AUDIT_AUDIT_CONFIG_HPP
