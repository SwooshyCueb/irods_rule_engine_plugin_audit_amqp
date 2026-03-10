#include "irods/private/audit_amqp.hpp"
#include "irods/private/amqp_sender.hpp"

#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_error.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_server_properties.hpp>
#include <irods/rodsErrorTable.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <ostream>
#include <thread>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <proton/connection.hpp>
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/error_condition.hpp>
#include <proton/message.hpp>
#include <proton/receiver.hpp>
#include <proton/reconnect_options.hpp>
#include <proton/sender.hpp>
#include <proton/sender_options.hpp>
#include <proton/session.hpp>
#include <proton/target_options.hpp>
#include <proton/timestamp.hpp>
#include <proton/tracker.hpp>
#include <proton/transport.hpp>
#include <proton/work_queue.hpp>

namespace irods::plugin::rule_engine::audit_amqp
{
	amqp_sender::amqp_sender()
		: _is_configured(false)
		, _is_open(false)
	{ }

	amqp_sender::~amqp_sender()
	{
		close();
	}

	irods::error amqp_sender::configure(const std::string& re_instance_name,
	                                    const std::string& url,
	                                    const std::string& node,
	                                    const std::string& user,
	                                    const std::string& password,
	                                    const std::optional<bool> sasl_enabled,
	                                    const std::optional<std::string> sasl_mechanisms,
	                                    const std::optional<bool> sasl_allow_insecure,
	                                    const std::optional<bool> durable_messages)
	{
		if (_is_open) {
			return ERROR(SYS_ALREADY_INITIALIZED, "amqp_sender::configure called on open amqp_sender");
		}
		if (url.empty()) {
			return ERROR(SYS_INVALID_SERVER_HOST, "amqp_sender::configure called with empty url");
		}

		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name},
			{"call", __PRETTY_FUNCTION__},
			{"url", url},
			{"node", node},
		});
		#endif
		// clang-format on

		_re_instance_name = re_instance_name;
		_url = url;
		_node = node;
		_user = user;
		_password = password;
		_sasl_enabled = sasl_enabled;
		_sasl_mechanisms = sasl_mechanisms;
		_sasl_allow_insecure = sasl_allow_insecure;
		_durable_messages = durable_messages;

		_is_configured = true;

		return SUCCESS();
	}

	irods::error amqp_sender::unconfigure()
	{
		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__}
		});
		#endif
		// clang-format on

		if (_is_open) {
			return ERROR(RE_RUNTIME_ERROR, "amqp_sender::unconfigure called on open amqp_sender");
		}

		_is_configured = false;

		return SUCCESS();
	}

	irods::error amqp_sender::open()
	{
		if (!_is_configured) {
			return ERROR(SYS_UNINITIALIZED, "amqp_sender::open called on unconfigured amqp_sender");
		}

		close();

		// This is after the call to close to avoid the potentially confusing situation of having the log entry for the
		// close call immediately following the log entry for the open call.
		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__}
		});
		#endif
		// clang-format on

		proton::connection_options conn_opts;
		proton::reconnect_options reconn_opts;
		conn_opts.handler(*this);
		conn_opts.reconnect(reconn_opts);
		if (!_user.empty()) {
			conn_opts.user(_user);
		}
		if (!_password.empty()) {
			conn_opts.password(_password);
		}
		if (_sasl_enabled.has_value()) {
			conn_opts.sasl_enabled(*_sasl_enabled);
		}
		if (_sasl_mechanisms.has_value()) {
			conn_opts.sasl_allowed_mechs(*_sasl_mechanisms);
		}
		if (_sasl_allow_insecure.has_value()) {
			conn_opts.sasl_allow_insecure_mechs(*_sasl_allow_insecure);
		}

		proton::sender_options sender_opts;
		proton::target_options target_opts;
		sender_opts.handler(*this);
		sender_opts.target(target_opts);

		_container.emplace(*this);
		proton::container& container = *_container;

		container.client_connection_options(conn_opts);
		container.sender_options(sender_opts);

		_is_open = true;

		_proton_thread.emplace([&container]() { container.run(); });

		return SUCCESS();
	}

	void amqp_sender::close()
	{
		const std::scoped_lock<std::mutex> lock(_proton_mutex);

		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		#endif
		// clang-format on

		if (_sender.has_value()) {
			proton::sender& sender = *_sender;
			sender.work_queue().add([&sender]() {
				if (!sender.closed()) {
					sender.close();
				}
			});
		}

		_is_open = false;

		if (_connection.has_value()) {
			proton::connection& connection = *_connection;
			connection.work_queue().add([&connection]() {
				if (!connection.closed()) {
					connection.close();
				}
			});
		}

		if (_container.has_value()) {
			_container->stop();
		}

		if (_proton_thread.has_value()) {
			if (_proton_thread->joinable()) {
				_proton_thread->join();
			}
		}

		_sender.reset();
		_connection.reset();
		_container.reset();
	}

	void amqp_sender::send_message(nlohmann::json& message_body,
	                               const std::uint64_t timestamp_ms,
	                               const pid_t pid,
	                               std::ofstream& test_log_ofstream)
	{
		const std::scoped_lock<std::mutex> lock(_proton_mutex);

		if (!(_is_open || _sender.has_value())) {
			THROW(SYS_UNINITIALIZED, "send_message called on closed amqp_sender");
		}

		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		#endif
		// clang-format on

		message_body["@timestamp"] = timestamp_ms;
		message_body["hostname"] = irods::get_server_property<std::string>(irods::KW_CFG_HOST);
		message_body["pid"] = pid;

		const std::string msg_str = message_body.dump();

		proton::message msg(msg_str);
		msg.content_type("application/json");
		msg.creation_time(proton::timestamp(static_cast<proton::timestamp::numeric_type>(timestamp_ms)));
		if (_durable_messages.has_value()) {
			msg.durable(*_durable_messages);
		}

		proton::sender& sender = *_sender;
		sender.work_queue().add([&sender, &msg]() { sender.send(msg); });

		if (test_log_ofstream.is_open()) {
			const std::string pid_str = fmt::to_string(pid);
			// clang-format off
			#ifdef IRODS_AUDIT_EXTRA_TRACE
			log_re::trace({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", _re_instance_name},
				{"pid", pid_str},
				{"log_message", "Writing amqp message to test log."}
			});
			#endif
			// clang-format on
			test_log_ofstream << msg_str << '\n' << std::flush;
			if (!test_log_ofstream.good()) {
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", _re_instance_name},
					{"pid", pid_str},
					{"log_message", "Error while writing to test log."}
				});
				// clang-format on
			}
		}
	}

	void amqp_sender::on_container_start([[maybe_unused]] proton::container& container)
	{
		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		#endif
		// clang-format on

		proton::connection_options conn_opts;
		proton::reconnect_options reconn_opts;
		conn_opts.handler(*this);
		conn_opts.reconnect(reconn_opts);
		if (!_user.empty()) {
			conn_opts.user(_user);
		}
		if (!_password.empty()) {
			conn_opts.password(_password);
		}
		if (_sasl_enabled.has_value()) {
			conn_opts.sasl_enabled(*_sasl_enabled);
		}
		if (_sasl_mechanisms.has_value()) {
			conn_opts.sasl_allowed_mechs(*_sasl_mechanisms);
		}
		if (_sasl_allow_insecure.has_value()) {
			conn_opts.sasl_allow_insecure_mechs(*_sasl_allow_insecure);
		}

		container.connect(_url, conn_opts);
	}

	void amqp_sender::on_connection_open([[maybe_unused]] proton::connection& connection)
	{
		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		#endif
		// clang-format on

		_connection = connection;

		proton::sender_options sender_opts;
		proton::target_options target_opts;
		sender_opts.handler(*this);
		sender_opts.target(target_opts);

		connection.open_sender(_node, sender_opts);
	}

	void amqp_sender::on_sender_open([[maybe_unused]] proton::sender& sender)
	{
		const std::scoped_lock<std::mutex> lock(_proton_mutex);

		// clang-format off
		#ifdef IRODS_AUDIT_EXTRA_TRACE
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		#endif
		// clang-format on

		_sender = sender;
	}

	void amqp_sender::on_tracker_reject([[maybe_unused]] proton::tracker& tracker)
	{
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"log_message", "AMQP server unexpectedly rejected message"}
		});
		// clang-format on
	}

	void amqp_sender::on_transport_error(proton::transport& transport)
	{
		const proton::error_condition& err_cond = transport.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"log_message", "Transport error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_connection_error(proton::connection& connection)
	{
		const proton::error_condition& err_cond = connection.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"log_message", "Connection error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_session_error(proton::session& session)
	{
		const proton::error_condition& err_cond = session.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"log_message", "Session error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_receiver_error(proton::receiver& receiver)
	{
		const proton::error_condition& err_cond = receiver.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"log_message", "Receiver error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_sender_error(proton::sender& sender)
	{
		const proton::error_condition& err_cond = sender.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"log_message", "Sender error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_error(const proton::error_condition& err_cond)
	{
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"log_message", "Unknown error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

#ifdef IRODS_AUDIT_EXTRA_TRACE
	void amqp_sender::on_container_stop([[maybe_unused]] proton::container& container)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sendable([[maybe_unused]] proton::sender& sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_transport_open([[maybe_unused]] proton::transport& transport)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_transport_close([[maybe_unused]] proton::transport& transport)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_connection_close([[maybe_unused]] proton::connection& connection)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_session_open([[maybe_unused]] proton::session& session)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_session_close([[maybe_unused]] proton::session& session)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_receiver_open([[maybe_unused]] proton::receiver& receiver)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_receiver_detach([[maybe_unused]] proton::receiver& receiver)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_receiver_close([[maybe_unused]] proton::receiver& receiver)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_detach([[maybe_unused]] proton::sender& sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_close([[maybe_unused]] proton::sender& sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_tracker_accept([[maybe_unused]] proton::tracker& tracker)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_tracker_release([[maybe_unused]] proton::tracker& tracker)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_tracker_settle([[maybe_unused]] proton::tracker& tracker)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_delivery_settle([[maybe_unused]] proton::delivery& delivery)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_drain_start([[maybe_unused]] proton::sender& sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_receiver_drain_finish([[maybe_unused]] proton::receiver& receiver)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_connection_wake([[maybe_unused]] proton::connection& connection)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}
#endif

} //namespace irods::plugin::rule_engine::audit_amqp
