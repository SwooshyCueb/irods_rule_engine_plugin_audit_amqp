#include "irods/private/audit_amqp.hpp"
#include "irods/private/amqp_config.hpp"
#include "irods/private/amqp_sender.hpp"

#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_error.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_server_properties.hpp>
#include <irods/rodsErrorTable.h>

#include <fmt/format.h>
#include <fmt/compile.h>

#include <nlohmann/json.hpp>

#include <proton/connection.hpp>
#include <proton/connection_options.hpp>
#include <proton/container.hpp>
#include <proton/error.hpp>
#include <proton/error_condition.hpp>
#include <proton/message.hpp>
#include <proton/sender.hpp>
#include <proton/sender_options.hpp>
#include <proton/session.hpp>
#include <proton/timestamp.hpp>
#include <proton/tracker.hpp>
#include <proton/transport.hpp>
#include <proton/work_queue.hpp>

#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <exception>
#include <mutex>
#include <optional>
#include <ostream>
#include <semaphore>
#include <string>
#include <thread>
#include <vector>

namespace irods::plugin::rule_engine::audit_amqp
{
	amqp_sender::amqp_sender()
		: is_open_(false)
		, connection_sem_(0)
	{ }

	amqp_sender::~amqp_sender()
	{
		close();
	}

	irods::error amqp_sender::configure(const std::string& _re_instance_name, const amqp_config& _amqp_config)
	{
		if (is_open_) {
			return ERROR(SYS_ALREADY_INITIALIZED, "amqp_sender::configure called on open amqp_sender");
		}
		if (!_amqp_config.is_initialized()) {
			return ERROR(SYS_UNINITIALIZED, "amqp_sender::configure called with uninitialized amqp_config argument");
		}

#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		std::vector<irods::experimental::log::key_value> log_kvs({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", _re_instance_name},
			{"call", __PRETTY_FUNCTION__},
			{"primary_endpoint", _amqp_config.primary_endpoint()},
		});
		// clang-format on
		std::uint32_t ep_ctr = 0;
		for (const std::string& endpoint : _amqp_config.failover_endpoints()) {
			log_kvs.emplace_back(fmt::format(FMT_COMPILE("failover_endpoint_{0:02d}"), ep_ctr++), endpoint);
		}
		log_kvs.emplace_back("path", _amqp_config.path());
		log_re::trace(log_kvs);
#endif

		re_instance_name_ = _re_instance_name;
		amqp_config_ = _amqp_config;

		return SUCCESS();
	}

	irods::error amqp_sender::unconfigure()
	{
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__}
		});
		// clang-format on
#endif

		if (is_open_) {
			return ERROR(RE_RUNTIME_ERROR, "amqp_sender::unconfigure called on open amqp_sender");
		}

		amqp_config_.deinitialize();

		return SUCCESS();
	}

	irods::error amqp_sender::open()
	{
		if (!amqp_config_.is_initialized()) {
			return ERROR(SYS_UNINITIALIZED, "amqp_sender::open called on unconfigured amqp_sender");
		}

		close();

		// This is after the call to close to avoid the potentially confusing situation of having the log entry for the
		// close call immediately following the log entry for the open call.
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		std::vector<irods::experimental::log::key_value> log_kvs({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
			{"primary_endpoint", amqp_config_.primary_endpoint()},
		});
		// clang-format on
		std::uint32_t ep_ctr = 0;
		for (const std::string& endpoint : amqp_config_.failover_endpoints()) {
			log_kvs.emplace_back(fmt::format(FMT_COMPILE("failover_endpoint_{0:02d}"), ep_ctr++), endpoint);
		}
		log_kvs.emplace_back("path", amqp_config_.path());
		log_re::trace(log_kvs);
#endif

		proton::connection_options conn_opts;
		conn_opts.handler(*this);
		amqp_config_.configure_connection(conn_opts, re_instance_name_);

		proton::sender_options sender_opts;
		sender_opts.handler(*this);
		amqp_config_.configure_sender(sender_opts);

		container_.emplace(*this);
		proton::container& container = *container_;

		container.client_connection_options(conn_opts);
		container.sender_options(sender_opts);

		proton_thread_.emplace([&container]() { container.run(); });
		if (amqp_config_.connection_open_timeout() > std::chrono::milliseconds::zero()) {
			if (!connection_sem_.try_acquire_for(amqp_config_.connection_open_timeout())) {
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Reached timeout while establishing AMQP connection."}
				});
				// clang-format on
			}
		}
		else {
			connection_sem_.acquire();
		}

		return SUCCESS();
	}

	void amqp_sender::close()
	{
		const std::scoped_lock<std::mutex> send_lock(amqp_send_mutex_);

#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
#endif

		if (sender_.has_value()) {
			std::binary_semaphore sender_disconn_sem(0);
			proton::sender& sender = *sender_;
			bool wq_res = sender.work_queue().add([&sender, &sender_disconn_sem]() {
				if (!sender.closed()) {
					sender.close();
				}
				sender_disconn_sem.release();
			});
			if (wq_res) {
				if (amqp_config_.sender_close_timeout() > std::chrono::milliseconds::zero()) {
					if (!sender_disconn_sem.try_acquire_for(amqp_config_.sender_close_timeout())) {
						// clang-format off
						log_re::error({
							{"rule_engine_plugin", rule_engine_name},
							{"instance_name", re_instance_name_},
							{"log_message", "Reached timeout while closing AMQP sender."}
						});
						// clang-format on
					}
				}
				else {
					sender_disconn_sem.acquire();
				}
#ifdef IRODS_AUDIT_EXTRA_TRACE
				// clang-format off
				log_re::trace({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "AMQP sender closed"},
				});
				// clang-format on
#endif
			}
			else {
				// clang-format off
				log_re::warn({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Could not queue AMQP sender close call"},
				});
				// clang-format on
			}

			std::binary_semaphore session_disconn_sem(0);
			proton::session session = sender.session();
			wq_res = session.work_queue().add([&session, &session_disconn_sem]() {
				if (!session.closed()) {
					session.close();
				}
				session_disconn_sem.release();
			});
			if (wq_res) {
				if (amqp_config_.session_close_timeout() > std::chrono::milliseconds::zero()) {
					if (!session_disconn_sem.try_acquire_for(amqp_config_.session_close_timeout())) {
						// clang-format off
						log_re::error({
							{"rule_engine_plugin", rule_engine_name},
							{"instance_name", re_instance_name_},
							{"log_message", "Reached timeout while closing AMQP session."}
						});
						// clang-format on
					}
				}
				else {
					session_disconn_sem.acquire();
				}
#ifdef IRODS_AUDIT_EXTRA_TRACE
				// clang-format off
				log_re::trace({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "AMQP session closed"},
				});
				// clang-format on
#endif
			}
			else {
				// clang-format off
				log_re::warn({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Could not queue AMQP session close call"},
				});
				// clang-format on
			}
		}

		is_open_ = false;

		bool did_close_conn = false;
		if (connection_.has_value()) {
			std::binary_semaphore connection_disconn_sem(0);
			proton::connection& connection = *connection_;
			const bool wq_res = connection.work_queue().add([&connection, &connection_disconn_sem]() {
				if (!connection.closed()) {
					connection.close();
				}
				connection_disconn_sem.release();
			});
			if (wq_res) {
				if (amqp_config_.connection_close_timeout() > std::chrono::milliseconds::zero()) {
					if (!connection_disconn_sem.try_acquire_for(amqp_config_.connection_close_timeout())) {
						// clang-format off
						log_re::error({
							{"rule_engine_plugin", rule_engine_name},
							{"instance_name", re_instance_name_},
							{"log_message", "Reached timeout while closing AMQP connection."}
						});
						// clang-format on
					}
				}
				else {
					connection_disconn_sem.acquire();
				}
				did_close_conn = true;
#ifdef IRODS_AUDIT_EXTRA_TRACE
				// clang-format off
				log_re::trace({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "AMQP connection closed"},
				});
#endif
				// clang-format on
			}
			else {
				// clang-format off
				log_re::warn({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Could not queue AMQP connection close call"},
				});
				// clang-format on
			}
		}

		if (container_.has_value() && !did_close_conn) {
			container_->stop();
#ifdef IRODS_AUDIT_EXTRA_TRACE
			// clang-format off
			log_re::trace({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", re_instance_name_},
				{"log_message", "AMQP container stopped"},
			});
#endif
			// clang-format on
		}

		if (proton_thread_.has_value()) {
			if (proton_thread_->joinable()) {
				proton_thread_->join();
#ifdef IRODS_AUDIT_EXTRA_TRACE
				// clang-format off
				log_re::trace({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Proton thread joined"},
				});
#endif
				// clang-format on
			}
			else {
				// clang-format off
				log_re::debug({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Proton thread not joinable"},
				});
				// clang-format on
			}
		}

		sender_.reset();
		connection_.reset();
		container_.reset();
		proton_thread_.reset();
	}

	void amqp_sender::send_message(nlohmann::json& _message_body,
	                               const std::uint64_t _timestamp_ms,
	                               const pid_t _pid,
	                               std::ofstream& _test_log_ofstream)
	{
		const std::scoped_lock<std::mutex> send_lock(amqp_send_mutex_);

		if (!(is_open_ && sender_.has_value())) {
			THROW(SYS_UNINITIALIZED, "send_message called on closed amqp_sender");
		}

#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
#endif

		_message_body["@timestamp"] = _timestamp_ms;
		_message_body["hostname"] = irods::get_server_property<std::string>(irods::KW_CFG_HOST);
		_message_body["pid"] = _pid;

		const std::string msg_str = _message_body.dump();

		proton::message msg(msg_str);
		msg.content_type("application/json");
		msg.creation_time(proton::timestamp(static_cast<proton::timestamp::numeric_type>(_timestamp_ms)));
		if (amqp_config_.durable_messages().has_value()) {
			msg.durable(*amqp_config_.durable_messages());
		}

		std::binary_semaphore send_semaphore(0);
		proton::sender& sender = *sender_;
		std::exception_ptr send_e;
		const bool is_sending = sender.work_queue().add([&sender, &msg, &send_semaphore, &send_e]() {
			try {
				const proton::tracker t = sender.send(msg);
#ifdef IRODS_AUDIT_EXTRA_TRACE
				// clang-format off
				log_re::debug({
					{"rule_engine_plugin", rule_engine_name},
					{"tracker::state", std::to_string(t.state())},
				});
				// clang-format on
#endif
			}
			catch (const std::exception& e) {
				send_e = std::current_exception();
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"log_message", "Exception thrown while sending AMQP message."},
					{"exception", e.what()}
				});
				// clang-format on
			}
			send_semaphore.release();
		});
		if (is_sending) {
			if (amqp_config_.message_send_timeout() > std::chrono::milliseconds::zero()) {
				if (!send_semaphore.try_acquire_for(amqp_config_.message_send_timeout())) {
					// clang-format off
					log_re::error({
						{"rule_engine_plugin", rule_engine_name},
						{"instance_name", re_instance_name_},
						{"log_message", "Reached timeout while sending AMQP message."}
					});
					// clang-format on
				}
			}
			else {
				send_semaphore.acquire();
			}
			if (send_e) {
				std::rethrow_exception(send_e);
			}
		}
		else {
			// clang-format off
			log_re::error({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", re_instance_name_},
				{"log_message", "Could not add message to work queue."}
			});
			// clang-format on
		}

		if (_test_log_ofstream.is_open()) {
#ifdef IRODS_AUDIT_EXTRA_TRACE
			// clang-format off
			log_re::trace({
				{"rule_engine_plugin", rule_engine_name},
				{"instance_name", re_instance_name_},
				{"log_message", "Writing amqp message to test log."}
			});
			// clang-format on
#endif
			_test_log_ofstream << msg_str << '\n' << std::flush;
			if (!_test_log_ofstream.good()) {
				// clang-format off
				log_re::error({
					{"rule_engine_plugin", rule_engine_name},
					{"instance_name", re_instance_name_},
					{"log_message", "Error while writing to test log."}
				});
				// clang-format on
			}
		}
	}

	void amqp_sender::on_container_start([[maybe_unused]] proton::container& _container)
	{
#ifdef IRODS_AUDIT_EXTRA_TRACE
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
#endif

		proton::connection_options conn_opts;
		conn_opts.handler(*this);
		amqp_config_.configure_connection(conn_opts, re_instance_name_);

		proton::sender_options sender_opts;
		sender_opts.handler(*this);
		amqp_config_.configure_sender(sender_opts);

		connection_ = _container.connect(amqp_config_.primary_endpoint(), conn_opts);
		sender_ = connection_->open_sender(amqp_config_.path(), sender_opts);

		is_open_ = true;

		connection_sem_.release();
	}

	void amqp_sender::on_tracker_reject([[maybe_unused]] proton::tracker& _tracker)
	{
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"log_message", "AMQP server unexpectedly rejected message"}
		});
		// clang-format on
	}

	void amqp_sender::on_transport_error(proton::transport& _transport)
	{
		const proton::error_condition& err_cond = _transport.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"log_message", "Transport error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_connection_error(proton::connection& _connection)
	{
		const proton::error_condition& err_cond = _connection.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"log_message", "Connection error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_session_error(proton::session& _session)
	{
		const proton::error_condition& err_cond = _session.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"log_message", "Session error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_sender_error(proton::sender& _sender)
	{
		const proton::error_condition& err_cond = _sender.error();
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"log_message", "Sender error in proton messaging handler"},
			{"error_condition::name", err_cond.name()},
			{"error_condition::description", err_cond.description()},
			{"error_condition::what", err_cond.what()}
		});
		// clang-format on
	}

	void amqp_sender::on_error(const proton::error_condition& _err_cond)
	{
		// clang-format off
		log_re::error({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"log_message", "Unknown error in proton messaging handler"},
			{"error_condition::name", _err_cond.name()},
			{"error_condition::description", _err_cond.description()},
			{"error_condition::what", _err_cond.what()}
		});
		// clang-format on
	}

#ifdef IRODS_AUDIT_EXTRA_TRACE
	void amqp_sender::on_container_stop([[maybe_unused]] proton::container& _container)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sendable([[maybe_unused]] proton::sender& _sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_transport_open([[maybe_unused]] proton::transport& _transport)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_transport_close([[maybe_unused]] proton::transport& _transport)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_connection_open([[maybe_unused]] proton::connection& _connection)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_connection_close([[maybe_unused]] proton::connection& _connection)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_session_open([[maybe_unused]] proton::session& _session)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_session_close([[maybe_unused]] proton::session& _session)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_open([[maybe_unused]] proton::sender& _sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_detach([[maybe_unused]] proton::sender& _sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_close([[maybe_unused]] proton::sender& _sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_tracker_accept([[maybe_unused]] proton::tracker& _tracker)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_tracker_release([[maybe_unused]] proton::tracker& _tracker)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_tracker_settle([[maybe_unused]] proton::tracker& _tracker)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_sender_drain_start([[maybe_unused]] proton::sender& _sender)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}

	void amqp_sender::on_connection_wake([[maybe_unused]] proton::connection& _connection)
	{
		// clang-format off
		log_re::trace({
			{"rule_engine_plugin", rule_engine_name},
			{"instance_name", re_instance_name_},
			{"call", __PRETTY_FUNCTION__},
		});
		// clang-format on
	}
#endif // IRODS_AUDIT_EXTRA_TRACE
} //namespace irods::plugin::rule_engine::audit_amqp
