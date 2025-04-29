## RBA Types

`contentctl` v5 has drastically simplified the configuration for Risk Based Alerting compared to previous versions. This page will serve as a changelog for the accepted values for a `risk_object_type` and `threat_object_type` as well as a brief description of each value.

### Risk Object Types

| Risk Object Type | Description                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------- |
| `user`             | usernames, emails, anything that ties back to a specific user                                 |
| `system`           | hostnames, IP Addresses, thing that tie back to a known device                                |
| `other`            | An escape hatch if you want to track risk against something that is neither a user nor system |

### Threat Object Types

| Threat Object Type       | Description                                          |
| ------------------------ | ---------------------------------------------------- |
| `certificate_common_name`  | A certificate owner's common name                    |
| `certificate_organization` | A certificate owner's organization                   |
| `certificate_serial`       | The certificate's serial number                      |
| `certificate_unit`         | The certificate owner's organizational unit          |
| `command`                  | A command (Frequently, from the Change Datamodel)    |
| `domain`                   | A domain name                                        |
| `email_address`            | An email address                                     |
| `email_subject`           | The subject line of an email                         |
| `file_hash`                | A file hash                                          |
| `file_name`                | A file's name                                        |
| `file_path`                | A file's path                                        |
| `http_user_agent`          | An HTTP User Agent                                   |
| `ip_address`               | An IP Address                                        |
| `process`                  | The full command line string of a process invocation |
| `process_name`             | The friendly name of a process                       |
| `parent_process`           | The full command line string of the parent process   |
| `parent_process_name`      | The friendly name of a parent process                |
| `process_hash`             | The digests of a process                             |
| `registry_path`            | The path to a registry value                         |
| `registry_value_name`      | The name of the registry value                       |
| `registry_value_text`      | The textual representation of registry_value_data    |
| `service`                  | The full service name                                |
| `signature`                | A human readable event name                          |
| `system`                   | A device or application identifier                   |
| `tls_hash`                 | The hash of a certificate                            |
| `url`                      | The URL of the requested resource                    |

> Last Updated: 2025.02.04, in prep for v5.1.0 of contentctl
