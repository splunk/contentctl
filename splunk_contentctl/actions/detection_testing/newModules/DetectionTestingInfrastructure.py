import threading
from pydantic import BaseModel, PrivateAttr
import abc
import requests
import splunklib.client as client

from splunk_contentctl.objects.test_config import TestConfig

from typing import Union
import configparser
from ssl import SSLEOFError
import time


class DetectionTestingInfrastructure(BaseModel, abc.ABC):
    # thread: threading.Thread = threading.Thread()
    config: TestConfig
    _conn: client.Service = PrivateAttr()

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data):
        super().__init__(**data)

    def setup(self):
        self.connect_to_api()
        self.configure_imported_roles()
        self.configure_delete_indexes()
        self.configure_conf_file_datamodels()

    def connect_to_api(self):

        while True:
            time.sleep(5)
            try:
                test_instance_api_port = 8089
                conn = client.connect(
                    host=self.config.test_instance_address,
                    port=test_instance_api_port,
                    username=self.config.splunk_app_username,
                    password=self.config.splunk_app_password,
                )
                if conn.restart_required:
                    # we will wait and try again
                    print("there is a pending restart")
                    continue
                # Finished setup
                self._conn = conn
                return
            except ConnectionRefusedError as e:
                raise (e)
            except SSLEOFError as e:
                print(
                    "Waiting to connect to Splunk Infrastructure for Configuration..."
                )
            except Exception as e:
                print(
                    f"Unhandled exception getting connection to splunk server: {str(e)}"
                )
                import sys

                sys.exit(1)

    def configure_imported_roles(
        self, imported_roles: list[str] = ["user", "power", "can_delete"]
    ):

        self._conn.roles.post(
            self.config.splunk_app_username, imported_roles=imported_roles
        )

    def configure_delete_indexes(self, indexes: list[str] = ["_*", "*", "main"]):
        endpoint = "/services/properties/authorize/default/deleteIndexesAllowed"
        indexes_encoded = ";".join(indexes)
        try:
            self._conn.post(endpoint, value=indexes_encoded)
        except Exception as e:
            print(
                f"Error configuring deleteIndexesAllowed with '{indexes_encoded}': [{str(e)}]"
            )

    def wait_for_conf_file(self, app_name: str, conf_file_name: str):
        while True:
            time.sleep(1)
            try:
                res = self._conn.get(f"configs/conf-{conf_file_name}", app=app_name)
                print(f"configs/conf-{conf_file_name} exists")
                return
            except Exception as e:
                print(f"Waiting for [{app_name} - {conf_file_name}.conf: {str(e)}")

    def configure_conf_file_datamodels(self, APP_NAME: str = "Splunk_SA_CIM"):
        self.wait_for_conf_file(APP_NAME, "datamodels")

        parser = configparser.ConfigParser()
        parser.read("/tmp/datamodels.conf")

        for datamodel_name in parser:
            if datamodel_name == "DEFAULT":
                print("Skipping the default for ConfigParser")
                continue
            for name, value in parser[datamodel_name].items():
                try:
                    res = self._conn.post(
                        f"properties/datamodels/{datamodel_name}/{name}",
                        app=APP_NAME,
                        value=value,
                    )

                except Exception as e:
                    print(
                        f"Error creating the conf Datamodel {datamodel_name} key/value {name}/{value}: {str(e)}"
                    )

    def execute(self):
        pass

    def status(self):
        pass

    def check_health(self):
        pass
