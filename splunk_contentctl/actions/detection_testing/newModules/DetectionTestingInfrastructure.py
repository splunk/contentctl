import threading
from pydantic import BaseModel, PrivateAttr
import abc
import requests
import splunklib.client as client

from splunk_contentctl.objects.test_config import (
    TestConfig,
    CONTAINER_APP_DIR,
    LOCAL_APP_DIR,
)

from typing import Union
import configparser
from ssl import SSLEOFError
import time
import uuid
import docker
import docker.models
import docker.models.resource
import docker.models.containers
import docker.types
import os


class DetectionTestingInfrastructure(BaseModel, abc.ABC):
    # thread: threading.Thread = threading.Thread()
    config: TestConfig
    hec_token: str = None
    hec_channel: str = None
    _conn: client.Service = PrivateAttr()

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data):
        super().__init__(**data)

    def start(self):
        raise (
            NotImplementedError(
                "start() is not implemented for Abstract Type DetectionTestingInfrastructure"
            )
        )

    def get_name(self) -> str:
        raise (
            NotImplementedError(
                "get_name() is not implemented for Abstract Type DetectionTestingInfrastructure"
            )
        )

    def setup(self):
        self.start()
        self.get_conn()
        self.configure_imported_roles()
        self.configure_delete_indexes()
        self.configure_conf_file_datamodels()
        self.configure_hec()
        self.wait_for_ui_ready()
        print("Finished and ready!")

    def wait_for_ui_ready(self):
        print("waiting for ui...")
        self.get_conn()
        print("done waiting for ui")

    def configure_hec(self):
        self.hec_channel = str(uuid.uuid4())
        try:
            res = self.get_conn().input(
                path="/servicesNS/nobody/splunk_httpinput/data/inputs/http/http:%2F%2FDETECTION_TESTING_HEC"
            )
            self.hec_token = str(res.token)
            print(
                f"HEC Endpoint for [{self.get_name()}] already exists with token [{self.hec_token}].  Using channel [{self.hec_channel}]"
            )
            return
        except Exception as e:
            # HEC input does not exist.  That's okay, we will create it
            pass

        try:

            res = self._conn.inputs.create(
                name="DETECTION_TESTING_HEC",
                kind="http",
                index="main",
                indexes="main,_internal,_audit",
                useACK=True,
            )
            self.hec_token = str(res.token)
            print(
                f"Successfully configured HEC Endpoint for [{self.get_name()}] with token [{self.hec_token}] and channel [{self.hec_channel}]"
            )
            return

        except Exception as e:
            raise (Exception(f"Failure creating HEC Endpoint: {str(e)}"))

    def get_conn(self) -> client.Service:
        try:
            if not self._conn:
                self.connect_to_api()
            elif self._conn.restart_required:
                # continue trying to re-establish a connection until after
                # the server has restarted
                self.connect_to_api()
        except Exception as e:
            # there was some issue getting the connection. Try again just once
            self.connect_to_api()
        return self._conn

    def connect_to_api(self):
        while True:
            time.sleep(5)
            try:

                conn = client.connect(
                    host=self.config.test_instance_address,
                    port=self.config.api_port,
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
                # Skip the DEFAULT section for configparser
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


class DetectionTestingContainer(DetectionTestingInfrastructure):
    container: docker.models.resource.Model = None

    def start(self):
        self.container = self.make_container()
        self.container.start()

    def get_name(self) -> str:
        return self.config.container_name

    def get_docker_client(self):
        try:
            c = docker.client.from_env()

            return c
        except Exception as e:
            raise (Exception(f"Failed to get docker client: {str(e)}"))

    def make_container(self) -> docker.models.resource.Model:
        # First, make sure that the container has been removed if it already existed
        self.removeContainer()
        print(f"In create hec {self.config.hec_port}")
        print(f"In create api {self.config.api_port}")
        ports_dict = {
            "8000/tcp": self.config.web_ui_port,
            "8088/tcp": self.config.hec_port,
            "8089/tcp": self.config.api_port,
        }

        mounts = [
            docker.types.Mount(
                source=str(LOCAL_APP_DIR.absolute()),
                target=str(CONTAINER_APP_DIR.absolute()),
                type="bind",
                read_only=True,
            )
        ]

        environment = {}
        environment["SPLUNK_START_ARGS"] = "--accept-license"
        environment["SPLUNK_PASSWORD"] = self.config.splunk_app_password
        environment["SPLUNK_APPS_URL"] = ",".join(
            p.environment_path for p in self.config.apps
        )
        if (
            self.config.splunkbase_password is not None
            and self.config.splunkbase_username is not None
        ):
            environment["SPLUNKBASE_USERNAME"] = self.config.splunkbase_username
            environment["SPLUNKBASE_PASSWORD"] = self.config.splunkbase_password

        container = self.get_docker_client().containers.create(
            self.config.full_image_path,
            ports=ports_dict,
            environment=environment,
            name=self.get_name(),
            mounts=mounts,
            detach=True,
        )

        return container

    def removeContainer(self, removeVolumes: bool = True, forceRemove: bool = True):

        try:
            container: docker.models.containers.Container = (
                self.get_docker_client().containers.get(self.get_name())
            )
        except Exception as e:
            # Container does not exist, no need to try and remove it
            return
        try:
            print("Removing container")
            # container was found, so now we try to remove it
            # v also removes volumes linked to the container
            container.remove(v=removeVolumes, force=forceRemove)
            # remove it even if it is running. remove volumes as well
            # No need to print that the container has been removed, it is expected behavior
            print("Container removed")

        except Exception as e:
            raise (
                Exception(
                    f"Could not remove Docker Container [{self.config.container_name}]: {str(e)}"
                )
            )
