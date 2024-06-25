from dataclasses import dataclass
from contentctl.input.director import DirectorInputDto
from contentctl.output.conf_output import ConfOutput


from typing import Union

@dataclass(frozen=True)
class ACSDeployInputDto:
    director_input_dto: DirectorInputDto
    splunk_api_username: str
    splunk_api_password: str
    splunk_cloud_jwt_token: str
    splunk_cloud_stack: str
    stack_type: str


class Deploy:
    def execute(self, input_dto: ACSDeployInputDto) -> None:
        
        conf_output = ConfOutput(input_dto.director_input_dto.input_path, input_dto.director_input_dto.config)
        
        appinspect_token = conf_output.inspectAppAPI(input_dto.splunk_api_username, input_dto.splunk_api_password, input_dto.stack_type)
        

        if input_dto.splunk_cloud_jwt_token is None or input_dto.splunk_cloud_stack is None:
            if input_dto.splunk_cloud_jwt_token is None:
                raise Exception("Cannot deploy app via ACS, --splunk_cloud_jwt_token was not defined on command line.")
            else:
                raise Exception("Cannot deploy app via ACS, --splunk_cloud_stack was not defined on command line.")
        
        conf_output.deploy_via_acs(input_dto.splunk_cloud_jwt_token,
                                input_dto.splunk_cloud_stack, 
                                appinspect_token,
                                input_dto.stack_type)

        
        