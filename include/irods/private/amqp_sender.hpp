#ifndef IRODS_AUDIT_AMQP_SENDER_HPP
#define IRODS_AUDIT_AMQP_SENDER_HPP

#include "irods/private/audit_amqp.hpp"

#include <irods/irods_error.hpp>

#include <cstdint>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include <boost/config.hpp>

#include <nlohmann/json.hpp>

#include <proton/connection.hpp>
#include <proton/container.hpp>
#include <proton/error_condition.hpp>
#include <proton/messaging_handler.hpp>
#include <proton/receiver.hpp>
#include <proton/sender.hpp>
#include <proton/session.hpp>
#include <proton/target.hpp>
#include <proton/tracker.hpp>
#include <proton/transport.hpp>

namespace irods::plugin::rule_engine::audit_amqp
{
	class amqp_sender : public proton::messaging_handler
	{
	  public:
		amqp_sender();
		~amqp_sender() override;

		irods::error configure(const std::string& re_instance_name,
		                       const std::string& url,
		                       const std::optional<bool> sasl_enabled,
		                       const std::optional<std::string> sasl_mechanisms,
		                       const std::optional<bool> sasl_allow_insecure,
		                       const std::optional<enum proton::target::durability_mode> sender_durability_mode,
		                       const std::optional<bool> durable_messages);
		irods::error unconfigure();

		irods::error open();
		void close();

		[[nodiscard]] BOOST_FORCEINLINE constexpr bool is_configured() const { return _is_configured; }
		[[nodiscard]] BOOST_FORCEINLINE constexpr bool is_open() const { return _is_open; }
		[[nodiscard]] BOOST_FORCEINLINE constexpr const std::string& re_instance_name() const { return _re_instance_name; }

		void send_message(nlohmann::json& message_body,
		                  const std::uint64_t timestamp_ms,
		                  const pid_t pid,
		                  std::ofstream& test_log_ofstream);

		void on_container_start(proton::container& container) override;
		void on_connection_open(proton::connection& connection) override;
		void on_sender_open(proton::sender& sender) override;
		void on_transport_error(proton::transport& transport) override;
		void on_connection_error(proton::connection& connection) override;
		void on_session_error(proton::session& session) override;
		void on_receiver_error(proton::receiver& receiver) override;
		void on_sender_error(proton::sender& sender) override;
		void on_tracker_reject(proton::tracker& tracker) override;
		void on_error(const proton::error_condition& err_cond) override;

		#ifdef IRODS_AUDIT_EXTRA_TRACE
		void on_container_stop(proton::container& container) override;
		void on_sendable(proton::sender& sender) override;
		void on_transport_open(proton::transport& transport) override;
		void on_transport_close(proton::transport& transport) override;
		void on_connection_close(proton::connection& connection) override;
		void on_session_open(proton::session& session) override;
		void on_session_close(proton::session& session) override;
		void on_receiver_open(proton::receiver& receiver) override;
		void on_receiver_detach(proton::receiver& receiver) override;
		void on_receiver_close(proton::receiver& receiver) override;
		void on_sender_detach(proton::sender& sender) override;
		void on_sender_close(proton::sender& sender) override;
		void on_tracker_accept(proton::tracker& tracker) override;
		void on_tracker_release(proton::tracker& tracker) override;
		void on_tracker_settle(proton::tracker& tracker) override;
		void on_delivery_settle(proton::delivery& delivery) override;
		void on_sender_drain_start(proton::sender& sender) override;
		void on_receiver_drain_finish(proton::receiver& receiver) override;
		void on_connection_wake(proton::connection& connection) override;
		#endif

	  private:
		bool _is_configured;
		bool _is_open;

		std::string _re_instance_name;

		std::string _url;
		std::optional<bool> _sasl_enabled;
		std::optional<std::string> _sasl_mechanisms;
		std::optional<bool> _sasl_allow_insecure;
		std::optional<enum proton::target::durability_mode> _sender_durability_mode;
		std::optional<bool> _durable_messages;

		std::mutex _proton_mutex;
		std::optional<std::thread> _proton_thread;

		std::optional<proton::container> _container;
		std::optional<proton::connection> _connection;
		std::optional<proton::sender> _sender;
	};
} //namespace irods::plugin::rule_engine::audit_amqp

#endif // IRODS_AUDIT_AMQP_SENDER_HPP
