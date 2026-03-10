from __future__ import print_function

from irods.configuration import IrodsConfig

def main():
    irods_config = IrodsConfig()
    irods_config.server_config['plugin_configuration']['rule_engines'].insert(1,
            {
                "instance_name": "irods_rule_engine_plugin-audit_amqp-instance",
                "plugin_name": "irods_rule_engine_plugin-audit_amqp",
                "plugin_specific_configuration": {
                    "pep_regex_to_match": "audit_.*",
                    "amqp_location": "ANONYMOUS@localhost:5672",
                    "amqp_topic": "audit_messages",
                    "amqp_sasl": {
                        "enable": True,
                        "allow_insecure": True
                    },
                    "amqp_durable_messages": True,
                    "test_mode": True,
                    "log_path_prefix": "/tmp/irods"
                }
            }
        )
    irods_config.server_config["rule_engine_namespaces"].append("audit_")
    irods_config.commit(irods_config.server_config, irods_config.server_config_path, make_backup=True)

if __name__ == '__main__':
    main()
