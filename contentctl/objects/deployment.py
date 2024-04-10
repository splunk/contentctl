from __future__ import annotations
from pydantic import Field, computed_field, model_validator
from typing import Optional

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.deployment_scheduling import DeploymentScheduling
from contentctl.objects.alert_action import AlertAction

from contentctl.objects.enums import DeploymentType


class Deployment(SecurityContentObject):
    #id: str = None
    #date: str = None
    #author: str = None
    #description: str = None
    #contentType: SecurityContentType = SecurityContentType.deployments
    scheduling: DeploymentScheduling = Field(...)
    alert_action: AlertAction = AlertAction()
    type: DeploymentType = Field(...)

    #Type was the only tag exposed and should likely be removed/refactored.
    #For transitional reasons, provide this as a computed_field in prep for removal
    @computed_field
    @property
    def tags(self)->dict[str,DeploymentType]:
        return {"type": self.type}
    