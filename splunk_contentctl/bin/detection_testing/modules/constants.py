ES_APP_NAME = "SPLUNK_ES_CONTENT_UPDATE"
DEFAULT_REPO_NAME = "https://github.com/splunk/security_content"

setup_schema = {
    "type": "object",
    "properties": {
        "main_branch": {
            "type": "string",
            "default": "develop"
        },
        "repo_url": {
            "type": "string",
            "default": DEFAULT_REPO_NAME
        },
        "branch": {
            "type": "string",
            "default": "develop"
        },
        "commit_hash": {
            "type": ["string", "null"],
            "default": None
        },

        "container_name": {
            "type": "string",
            "default": "latest"
        },

        "post_test_behavior": {
            "type": "string",
            "enum": ["always_pause", "pause_on_failure", "never_pause"],
            "default": "pause_on_failure"
        },

        "detections_list": {
            "type": ["array", "null"],
            "items": {
                "type": "string"
            },
            "default": None,
        },
        "apps": {
            "type": "object",
            "additionalProperties": False,
            "patternProperties": {
                "^.*$": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "app_number": {
                            "type": ["integer", "null"]
                        },
                        "app_version": {
                            "type": ["string", "null"]
                        },
                        "local_path": {
                            "type": ["string", "null"]
                        },
                        "http_path": {
                            "type": ["string", "null"]
                        }
                    },
                    "anyOf": [
                        {"required": ["local_path"]},
                        {"required": ["http_path"]},
                        {"required": ["app_number", "app_version"]},
                    ]
                }
            },
            "default": {

                # The default apps below were taken from the attack_range loadout: https://github.com/splunk/attack_range/blob/develop/attack_range.conf.template

                "ADD_ON_FOR_LINUX_SYSMON": {
                    "app_number": 6176,
                    "app_version": "1.0.4",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/add-on-for-linux-sysmon_104.tgz"
                },
                ES_APP_NAME: {
                    "app_number": 3449,
                    "app_version": None,
                    "local_path": None
                },
                "PALO_ALTO_NETWORKS_ADD_ON_FOR_SPLUNK": {
                    "app_number": 2757,
                    "app_version": "7.1.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/palo-alto-networks-add-on-for-splunk_710.tgz"
                },
                "PYTHON_FOR_SCIENTIFIC_COMPUTING_FOR_LINUX_64_BIT": {
                    "app_number": 2882,
                    "app_version": "3.0.2",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/python-for-scientific-computing-for-linux-64-bit_302.tgz"
                },
                "SPLUNK_ADD_ON_FOR_AMAZON_KINESIS_FIREHOSE": {
                    "app_number": 3719,
                    "app_version": "1.3.2",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-amazon-kinesis-firehose_132.tgz"
                },
                "SPLUNK_ADD_ON_FOR_MICROSOFT_OFFICE_365": {
                    "app_number": 4055,
                    "app_version": "4.0.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-office-365_400.tgz"
                },
                "SPLUNK_ADD_ON_FOR_MICROSOFT_WINDOWS": {
                    "app_number": 742,
                    "app_version": "8.5.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-windows_850_PATCHED.tgz"
                },
                "SPLUNK_ADD_ON_FOR_NGINX": {
                    "app_number": 3258,
                    "app_version": "3.1.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-nginx_310.tgz"
                },
                "SPLUNK_ADD_ON_FOR_STREAM_FORWARDERS": {
                    "app_number": 5238,
                    "app_version": "8.1.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-stream-forwarders_810.tgz"
                },
                "SPLUNK_ADD_ON_FOR_STREAM_WIRE_DATA": {
                    "app_number": 5234,
                    "app_version": "8.1.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-stream-wire-data_810.tgz"
                },
                "SPLUNK_ADD_ON_FOR_SYSMON": {
                    "app_number": 5709,
                    "app_version": "3.0.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-sysmon_300.tgz"
                },
                "SPLUNK_ADD_ON_FOR_UNIX_AND_LINUX": {
                    "app_number": 833,
                    "app_version": "8.6.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-unix-and-linux_860.tgz"
                },
                "SPLUNK_APP_FOR_STREAM": {
                    "app_number": 1809,
                    "app_version": "8.1.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-app-for-stream_810.tgz"
                },
                "SPLUNK_COMMON_INFORMATION_MODEL": {
                    "app_number": 1621,
                    "app_version": "5.0.1",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-common-information-model-cim_501.tgz"
                },
                "SPLUNK_MACHINE_LEARNING_TOOLKIT": {
                    "app_number": 2890,
                    "app_version": "5.3.1",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-machine-learning-toolkit_531.tgz"
                },
                "SPLUNK_TA_FOR_ZEEK": {
                    "app_number": 5466,
                    "app_version": "1.0.5",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/ta-for-zeek_105.tgz"
                },
                "URL_TOOLBOX": {
                    "app_number": 2734,
                    "app_version": "1.9.2",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/url-toolbox_192.tgz"
                },
                "SPLUNK_TA_MICROSOFT_CLOUD_SERVICES": {
                    "app_number": 3110,
                    "app_version": "4.5.0",
                    "http_path": "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-cloud-services_450.tgz"
                }

            }
        },
        "mode": {
            "type": "string",
            "enum": ["changes", "selected", "all"],
            "default": "changes"
        },

        "num_containers": {
            "type": "integer",
            "minimum": 1,
            "default": 1
        },

        "pr_number": {
            "type": ["integer", "null"],
            "default": None
        },


        "splunk_app_password": {
            "type": "string"
        },

        "mock": {
            "type": "boolean",
            "default": False
        },

    },
    "if": {
        "properties": {"mode": {"const": "selected"}}
    },
    "then": {
        "properties": {"detections_list": {"type": "array",
                                           "items": {
                                               "type": "string"
                                           },
                                           }
                       }
    },
    "else": {
        "properties": {
            "detections_list": {
                "type": "null"
            }
        }
    }
}
