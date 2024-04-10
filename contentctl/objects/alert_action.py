from __future__ import annotations
from pydantic import BaseModel
from typing import Optional

from contentctl.objects.deployment_email import DeploymentEmail
from contentctl.objects.deployment_notable import DeploymentNotable
from contentctl.objects.deployment_rba import DeploymentRBA
from contentctl.objects.deployment_slack import DeploymentSlack
from contentctl.objects.deployment_phantom import DeploymentPhantom

class AlertAction(BaseModel):
    email: Optional[DeploymentEmail] = None
    notable: Optional[DeploymentNotable] = None
    rba: Optional[DeploymentRBA] = DeploymentRBA()
    slack: Optional[DeploymentSlack] = None
    phantom: Optional[DeploymentPhantom] = None
