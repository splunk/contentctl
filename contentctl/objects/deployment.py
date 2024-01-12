
import uuid
import string


from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.deployment_scheduling import DeploymentScheduling
from contentctl.objects.deployment_email import DeploymentEmail
from contentctl.objects.deployment_notable import DeploymentNotable
from contentctl.objects.deployment_rba import DeploymentRBA
from contentctl.objects.deployment_slack import DeploymentSlack
from contentctl.objects.deployment_phantom import DeploymentPhantom
from pydantic import Field, computed_field
from typing import Optional
from contentctl.objects.enums import DeploymentType

class Deployment(SecurityContentObject):
    #id: str = None
    #date: str = None
    #author: str = None
    #description: str = None
    #contentType: SecurityContentType = SecurityContentType.deployments
    scheduling: DeploymentScheduling = Field(...)
    email: Optional[DeploymentEmail] = None
    notable: Optional[DeploymentNotable] = None
    rba: Optional[DeploymentRBA] = None
    slack: Optional[DeploymentSlack] = None
    phantom: Optional[DeploymentPhantom] = None
    type: DeploymentType = Field(...)

    #Type was the only tag exposed and should likely be removed/refactored.
    #For transitional reasons, provide this as a computed_field in prep for removal
    @computed_field
    @property
    def tags(self)->dict[str,DeploymentType]:
        return {"type": self.type}
    