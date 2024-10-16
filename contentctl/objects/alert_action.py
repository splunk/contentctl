from __future__ import annotations
from pydantic import BaseModel, model_serializer
from typing import Optional

from contentctl.objects.deployment_email import DeploymentEmail
from contentctl.objects.deployment_notable import DeploymentNotable
from contentctl.objects.deployment_rba import DeploymentRBA
from contentctl.objects.deployment_slack import DeploymentSlack
from contentctl.objects.deployment_phantom import DeploymentPhantom
from contentctl.objects.deployment_jira import DeploymentJira
from contentctl.objects.deployment_pagerduty import DeploymentPagerDuty

class AlertAction(BaseModel):
    email: Optional[DeploymentEmail] = None
    notable: Optional[DeploymentNotable] = None
    rba: Optional[DeploymentRBA] = DeploymentRBA()
    slack: Optional[DeploymentSlack] = None
    phantom: Optional[DeploymentPhantom] = None
    jira: Optional[DeploymentJira] = None
    pagerduty: Optional[DeploymentPagerDuty] = None

    
    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        model = {}

        if self.email is not None:
            raise Exception("Email not implemented")

        if self.notable is not None:
            model['notable'] = self.notable

        if self.rba is not None and self.rba.enabled:
            model['rba'] = {'enabled': "true"}

        if self.slack is not None:
            raise Exception("Slack not implemented")
        
        if self.phantom is not None:
            raise Exception("Phantom not implemented")
        
        if self.jira is not None:
            raise Exception("Jira not implemented")
        
        if self.pagerduty is not None:
            raise Exception("PagerDuty not implemented")
        
        #return the model
        return model