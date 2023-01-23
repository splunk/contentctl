import threading
from pydantic import BaseModel, PrivateAttr
import abc
import requests
import splunklib.client as client

from splunk_contentctl.objects.test_config import TestConfig

from typing import Union
import configparser


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

        test_instance_api_port = 8089
        self._conn = client.connect(
            host=self.config.test_instance_address,
            port=test_instance_api_port,
            username=self.config.splunk_app_username,
            password=self.config.splunk_app_password,
        )

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

    def configure_conf_file_datamodels(self, APP_NAME: str = "Splunk_SA_CIM"):

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
