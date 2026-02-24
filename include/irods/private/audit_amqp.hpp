#ifndef IRODS_AUDIT_AMQP_MAIN_HPP
#define IRODS_AUDIT_AMQP_MAIN_HPP

#include <irods/irods_logger.hpp>

#include <chrono>
#include <string>

#include <boost/config.hpp>

namespace irods::plugin::rule_engine::audit_amqp
{
	static inline constexpr const char* const rule_engine_name = "audit_amqp";

	using log_re = irods::experimental::log::rule_engine;

#if __cpp_lib_chrono >= 201907
	// we use millisecond precision in our timestamps, so we want to use a clock
	// that does not implement leap seconds as repeated non-leap seconds, if we can.
	using ts_clock = std::chrono::utc_clock;
#else
	// fallback to system_clock
	using ts_clock = std::chrono::system_clock;
#endif

	template <class Logger>
	BOOST_FORCEINLINE void log_exception(const Logger& logger,
	                                     const std::string& log_message,
	                                     const std::string& e_what,
	                                     const std::string& instance_name,
	                                     const std::string& rule_name)
	{
		// clang-format off
		logger({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", instance_name},
			{"rule_name", rule_name},
			{"log_message", log_message},
			{"exception", e_what},
		});
		// clang-format on
	}

	template <class Logger>
	BOOST_FORCEINLINE void log_exception(const Logger& logger,
	                                     const std::string& log_message,
	                                     const std::string& e_what,
	                                     const std::string& instance_name)
	{
		// clang-format off
		logger({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", instance_name},
			{"log_message", log_message},
			{"exception", e_what},
		});
		// clang-format on
	}
} //namespace irods::plugin::rule_engine::audit_amqp

#endif // IRODS_AUDIT_AMQP_MAIN_HPP
