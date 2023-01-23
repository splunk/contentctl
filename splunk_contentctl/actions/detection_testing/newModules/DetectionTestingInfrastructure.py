import threading
from pydantic import BaseModel
import abc
import requests
import splunklib.client as client

from splunk_contentctl.objects.test_config import TestConfig


class DetectionTestingInfrastructure(BaseModel, abc.ABC):
    # thread: threading.Thread = threading.Thread()
    config: TestConfig
    conn: client.Service

    class Config:
        arbitrary_types_allowed = True

    def __init__(
        self,
        config: TestConfig,
    ):
        self.config = config
        self.conn = self.connect_to_api()

    def setup(self):
        pass

    def connect_to_api(self) -> client.Service:

        test_instance_api_port = 8089
        conn = client.connect(
            host=self.config.test_instance_address,
            port=test_instance_api_port,
            username=self.config.splunk_app_username,
            password=self.config.splunk_app_password,
        )

        return conn

    def configure_imported_roles(
        self, imported_roles: list[str] = ["user", "power", "can_delete"]
    ):

        self.conn.roles.post(
            self.config.splunk_app_username, imported_roles=imported_roles
        )

    def configure_delete_indexes(self, indexes: list[str] = ["_*", "*", "main"]):
        test_instance_api_port = 8089
        endpoint = "services/properties/authorize/default/deleteIndexesAllowed"
        indexes_encoded = ";".join(indexes)

        target = f"https://{self.config.test_instance_address}:{test_instance_api_port}/{endpoint}"
        # is there a way to do this with the Python API? Probably...
        res = requests.post(
            target,
            data={"value": indexes_encoded},
            verify=False,
            auth=(self.config.splunk_app_username, self.config.splunk_app_password),
        )
        res.raise_for_status()

    def configure_conf_file_datamodels(self):
        import configparser

        parser = configparser.ConfigParser()
        parser.read("/tmp/datamodels.conf")

        test_instance_api_port = 8089
        endpoint = "services/datamodel/model"
        target = f"https://{self.config.test_instance_address}:{test_instance_api_port}/{endpoint}"

        print("**************\n\n\n\n")
        print(target)

        # Create the conf file
        endpoint = "servicesNS/nobody/Splunk_SA_CIM/properties/"
        target = f"https://{self.config.test_instance_address}:{test_instance_api_port}/{endpoint}"
        data = {"__conf": "datamodels"}

        try:
            res = requests.post(
                target,
                data=data,
                verify=False,
                auth=(self.config.splunk_app_username, self.config.splunk_app_password),
            )
            res.raise_for_status()
        except Exception as e:
            print(f"Error creating the conf datafile: {str(e)}")
            sys.exit(1)

        for datamodel_name in parser:
            if datamodel_name == "DEFAULT":
                print("Skipping the default for ConfigParser")
                continue

            # Add the stanza
            endpoint = "servicesNS/nobody/Splunk_SA_CIM/configs/conf-datamodels"
            target = f"https://{self.config.test_instance_address}:{test_instance_api_port}/{endpoint}"
            data = {"name": datamodel_name}
            try:
                res = requests.post(
                    target,
                    data=data,
                    verify=False,
                    auth=(
                        self.config.splunk_app_username,
                        self.config.splunk_app_password,
                    ),
                )
                res.raise_for_status()
            except Exception as e:
                print(
                    f"Error creating the conf datamodel/stanza {datamodel_name}: {str(e)}"
                )
                sys.exit(1)

            endpoint = f"servicesNS/nobody/Splunk_SA_CIM/configs/conf-datamodels/{datamodel_name}"
            target = f"https://{self.config.test_instance_address}:{test_instance_api_port}/{endpoint}"
            for name, value in parser[datamodel_name].items():
                data = {name: value}
                try:
                    res = requests.post(
                        target,
                        data=data,
                        verify=False,
                        auth=(
                            self.config.splunk_app_username,
                            self.config.splunk_app_password,
                        ),
                    )
                    res.raise_for_status()

                except Exception as e:
                    print(
                        f"Error creating the conf stanza {data} key/value {name}/{value}: {str(e)}"
                    )
                    code.interact(local=locals())
                    sys.exit(1)

    def execute(self):
        pass

    def status(self):
        pass

    def check_health(self):
        pass
