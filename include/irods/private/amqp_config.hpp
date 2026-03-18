#ifndef IRODS_AUDIT_AUDIT_CONFIG_HPP
#define IRODS_AUDIT_AUDIT_CONFIG_HPP

#include "irods/private/audit_amqp.hpp"

#include <irods/irods_error.hpp>

#include <nlohmann/json.hpp>

#include <proton/connection_options.hpp>
#include <proton/duration.hpp>
#include <proton/target.hpp>

#include <cstdint>
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

			static constexpr const std::optional<std::uint32_t> connection_max_frame_size = std::nullopt;
			static constexpr const std::optional<std::uint16_t> connection_max_sessions = std::nullopt;
			static constexpr const auto connection_idle_timeout = std::nullopt;
			static constexpr const std::optional<std::string> connection_virtual_host = std::nullopt;
			static constexpr const auto reconnect_delay = std::nullopt;
			static constexpr const std::optional<float> reconnect_delay_multiplier = std::nullopt;
			static constexpr const auto reconnect_max_delay = std::nullopt;
			static constexpr const std::optional<int> reconnect_max_attempts = std::nullopt;

			static constexpr const std::optional<bool> sasl_enabled = std::nullopt;
			static constexpr const std::optional<std::string> sasl_mechanisms = std::nullopt;
			static constexpr const std::optional<bool> sasl_allow_insecure = std::nullopt;

			static constexpr const enum proton::target::durability_mode sender_durability_mode =
				proton::target::durability_mode::UNSETTLED_STATE;

			static constexpr const bool durable_messages = true;
		};

		irods::error initialize(const nlohmann::json& _plugin_specific_configuration,
		                        const std::string& _re_instance_name);

		void configure_connection(proton::connection_options& _conn_opts);

		void deinitialize()
		{
			is_initialized_ = false;

			primary_endpoint_.clear();
			failover_endpoints_.clear();

			path_.clear();

			user_.clear();
			password_.clear();

			connection_max_frame_size_ = std::nullopt;
			connection_max_sessions_ = std::nullopt;
			connection_idle_timeout_ = std::nullopt;
			connection_virtual_host_ = std::nullopt;
			reconnect_delay_ = std::nullopt;
			reconnect_delay_multiplier_ = std::nullopt;
			reconnect_max_delay_ = std::nullopt;
			reconnect_max_attempts_ = std::nullopt;

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

			connection_max_frame_size_ = defaults::connection_max_frame_size;
			connection_max_sessions_ = defaults::connection_max_sessions;
			connection_idle_timeout_ = defaults::connection_idle_timeout;
			connection_virtual_host_ = defaults::connection_virtual_host;
			reconnect_delay_ = defaults::reconnect_delay;
			reconnect_delay_multiplier_ = defaults::reconnect_delay_multiplier;
			reconnect_max_delay_ = defaults::reconnect_max_delay;
			reconnect_max_attempts_ = defaults::reconnect_max_attempts;

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
		[[nodiscard]] constexpr const std::optional<std::uint32_t>& connection_max_frame_size() const { return connection_max_frame_size_; }
		[[nodiscard]] constexpr const std::optional<std::uint16_t>& connection_max_sessions() const { return connection_max_sessions_; }
		[[nodiscard]] constexpr const std::optional<proton::duration>& connection_idle_timeout() const { return connection_idle_timeout_; }
		[[nodiscard]] constexpr const std::optional<std::string>& connection_virtual_host() const { return connection_virtual_host_; }
		[[nodiscard]] constexpr const std::optional<proton::duration>& reconnect_delay() const { return reconnect_delay_; }
		[[nodiscard]] constexpr const std::optional<float>& reconnect_delay_multiplier() const { return reconnect_delay_multiplier_; }
		[[nodiscard]] constexpr const std::optional<proton::duration>& reconnect_max_delay() const { return reconnect_max_delay_; }
		[[nodiscard]] constexpr const std::optional<int>& reconnect_max_attempts() const { return reconnect_max_attempts_; }
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

		std::optional<std::uint32_t> connection_max_frame_size_;
		std::optional<std::uint16_t> connection_max_sessions_;
		std::optional<proton::duration> connection_idle_timeout_;
		std::optional<std::string> connection_virtual_host_;
		std::optional<proton::duration> reconnect_delay_;
		std::optional<float> reconnect_delay_multiplier_;
		std::optional<proton::duration> reconnect_max_delay_;
		std::optional<int> reconnect_max_attempts_;

		std::optional<bool> sasl_enabled_;
		std::optional<std::string> sasl_mechanisms_;
		std::optional<bool> sasl_allow_insecure_;

		std::optional<enum proton::target::durability_mode> sender_durability_mode_;

		std::optional<bool> durable_messages_;

		static std::optional<amqp_config> default_instance_;
	};
} //namespace irods::plugin::rule_engine::audit_amqp

#endif // IRODS_AUDIT_AUDIT_CONFIG_HPP
