from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
)
from contentctl.objects.config import test
import docker.models.resource
import docker.models.containers
import docker
import docker.types


class DetectionTestingInfrastructureContainer(DetectionTestingInfrastructure):
    global_config: test
    container: docker.models.resource.Model = None

    def start(self):
        if self.global_config.container_settings.leave_running:
            # If we are configured to use the persistent container, then check and see if it's already
            # running. If so, just use it without additional configuration.
            try:
                self.container = self.get_docker_client().containers.get(self.get_name())
                return
            except Exception:
                #We did not find the container running, we will set it up
                pass

        self.container = self.make_container()
        self.container.start()

    def finish(self):
        if self.container is not None:
            try:
                self.removeContainer()
                pass
            except Exception as e:
                raise (Exception(f"Error removing container: {str(e)}"))
        super().finish()

    def get_name(self) -> str:
        return self.infrastructure.instance_name

    def get_docker_client(self):
        try:
            c = docker.client.from_env()

            return c
        except Exception as e:
            raise (Exception(f"Failed to get docker client: {str(e)}"))

    def check_for_teardown(self):

        try:
            self.get_docker_client().containers.get(self.get_name())
        except Exception as e:
            if self.sync_obj.terminate is not True:
                self.pbar.write(
                    f"Error: could not get container [{self.get_name()}]: {str(e)}"
                )
                self.sync_obj.terminate = True

        if self.sync_obj.terminate:
            self.finish()

        super().check_for_teardown()

    def make_container(self) -> docker.models.resource.Model:
        # First, make sure that the container has been removed if it already existed
        self.removeContainer()

        ports_dict = {
            "8000/tcp": self.infrastructure.web_ui_port,
            "8088/tcp": self.infrastructure.hec_port,
            "8089/tcp": self.infrastructure.api_port,
        }

        mounts = [
            docker.types.Mount(
                source=str(self.global_config.getLocalAppDir()),
                target=str(self.global_config.getContainerAppDir()),
                type="bind",
                read_only=True,
            )
        ]

        environment = {}
        environment["SPLUNK_START_ARGS"] = "--accept-license"
        environment["SPLUNK_PASSWORD"] = self.infrastructure.splunk_app_password
        # Files have already been staged by the time that we call this. Files must only be staged
        # once, not staged by every container
        environment["SPLUNK_APPS_URL"] = self.global_config.getContainerEnvironmentString(stage_file=False)
        if (
            self.global_config.splunk_api_username is not None
            and self.global_config.splunk_api_password is not None
        ):
            environment["SPLUNKBASE_USERNAME"] = self.global_config.splunk_api_username
            environment["SPLUNKBASE_PASSWORD"] = self.global_config.splunk_api_password
        


        def emit_docker_run_equivalent():
            environment_string = " ".join([f'-e "{k}={environment.get(k)}"' for k in environment.keys()])
            print(f"\n\ndocker run -d "\
                  f"-p {self.infrastructure.web_ui_port}:8000 "
                  f"-p {self.infrastructure.hec_port}:8088 "
                  f"-p {self.infrastructure.api_port}:8089 "
                  f"{environment_string} "            
                  f" --name {self.get_name()} "
                  f"--platform linux/amd64 "
                  f"{self.global_config.container_settings.full_image_path}\n\n")
        #emit_docker_run_equivalent()
        
        container = self.get_docker_client().containers.create(
            self.global_config.container_settings.full_image_path,
            ports=ports_dict,
            environment=environment,
            name=self.get_name(),
            mounts=mounts,
            detach=True,
            platform="linux/amd64"
        )
        
        if self.global_config.enterpriseSecurityInApps():
            #ES sets up https, so make sure it is included in the link
            address = f"https://{self.infrastructure.instance_address}:{self.infrastructure.web_ui_port}"
        else:
            address = f"http://{self.infrastructure.instance_address}:{self.infrastructure.web_ui_port}"
        print(f"\nStarted container with the following information:\n"
              f"\tname    : [{self.get_name()}]\n"
              f"\taddress : [{address}]\n"
              f"\tusername: [{self.infrastructure.splunk_app_username}]\n"
              f"\tpassword: [{self.infrastructure.splunk_app_password}]\n"
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
            # If the user wants to persist the container (or use a previously configured container), then DO NOT remove it.
            # Emit the following message, which they will see on initial setup and teardown at the end of the test. 
            if self.global_config.container_settings.leave_running:
                print(f"\nContainer [{self.get_name()}] has NOT been terminated because 'contentctl_test.yml ---> infrastructure_config ---> persist_and_reuse_container = True'")
                print(f"To remove it, please manually run the following at the command line: `docker container rm -fv {self.get_name()}`\n")
                return
            # container was found, so now we try to remove it
            # v also removes volumes linked to the container
            container.remove(v=removeVolumes, force=forceRemove)
            print(f"container [{self.get_name()}] successfully removed")

            # remove it even if it is running. remove volumes as well
            # No need to print that the container has been removed, it is expected behavior

        except Exception as e:
            raise (
                Exception(
                    f"Could not remove Docker Container [{self.get_name()}]: {str(e)}"
                )
            )
