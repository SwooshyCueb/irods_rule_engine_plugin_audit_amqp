#ifndef IRODS_AUDIT_AUDIT_CONFIG_HPP
#define IRODS_AUDIT_AUDIT_CONFIG_HPP

#include "irods/private/amqp_config.hpp"

#include <irods/irods_error.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <regex>
#include <string>

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
	class plugin_config
	{
	  public:
		class defaults
		{
		  public:
			defaults() = delete;

			static constexpr const std::regex::flag_type pep_regex_flags =
				std::regex::ECMAScript | std::regex::optimize;
			static constexpr const std::string pep_regex = "pep_.+";

			static constexpr const bool test_mode_enabled = false;
		};

		irods::error initialize(const nlohmann::json& _plugin_specific_configuration,
		                        const std::string& _re_instance_name);
		irods::error initialize(const std::string& _re_instance_name);

		void initialize_from_defaults()
		{
			is_configured_ = false;
			is_old_config_ = false;

			pep_regex_flags_ = defaults::pep_regex_flags;
			pep_regex_ = std::regex(defaults::pep_regex, pep_regex_flags_);

			test_mode_enabled_ = defaults::test_mode_enabled;
			test_mode_log_path_prefix_ = fs::temp_directory_path();

			amqp_config_.initialize_from_defaults();
		}

		[[nodiscard]] constexpr bool is_configured() const { return is_configured_; }
		[[nodiscard]] constexpr bool is_old_config() const { return is_old_config_; }

		// NOLINTBEGIN(readability-const-return-type)
		[[nodiscard]] constexpr const std::regex& pep_regex() const { return pep_regex_; }
		[[nodiscard]] constexpr bool test_mode_enabled() const { return test_mode_enabled_; }
		[[nodiscard]] constexpr const fs::path& test_mode_log_path_prefix() const { return test_mode_log_path_prefix_; }
		[[nodiscard]] constexpr const amqp_config& amqp_config() const { return amqp_config_; }
		// NOLINTEND(readability-const-return-type)

		static const plugin_config& default_config()
		{
			if (!default_instance_.has_value()) {
				plugin_config config;
				config.initialize_from_defaults();
				default_instance_ = config;
			}

			return *default_instance_;
		}

	  private:
		irods::error load_configuration(const nlohmann::json& _plugin_specific_configuration,
		                                const std::string& _re_instance_name);

		bool is_configured_{false};
		bool is_old_config_{false};

		std::regex::flag_type pep_regex_flags_;
		std::regex pep_regex_;

		bool test_mode_enabled_;
		fs::path test_mode_log_path_prefix_;

		class amqp_config amqp_config_;

		static std::optional<plugin_config> default_instance_;
	};
} //namespace irods::plugin::rule_engine::audit_amqp

#endif // IRODS_AUDIT_AUDIT_CONFIG_HPP
