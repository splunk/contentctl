from __future__ import annotations
from pydantic import Field, computed_field,ValidationInfo, model_serializer, NonNegativeInt, ConfigDict
from typing import Any
import uuid
import datetime
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.deployment_scheduling import DeploymentScheduling
from contentctl.objects.alert_action import AlertAction

from contentctl.objects.enums import DeploymentType


class Deployment(SecurityContentObject):    
    scheduling: DeploymentScheduling = Field(...)
    alert_action: AlertAction = AlertAction()
    type: DeploymentType = Field(...)
    author: str = Field(...,max_length=255)
    version: NonNegativeInt = 1

    #Type was the only tag exposed and should likely be removed/refactored.
    #For transitional reasons, provide this as a computed_field in prep for removal
    @computed_field
    @property
    def tags(self)->dict[str,DeploymentType]:
        return {"type": self.type}

        
    @staticmethod
    def getDeployment(v:dict[str,Any], info:ValidationInfo)->Deployment:
        if v != {}:
            # If the user has defined a deployment, then allow it to be validated
            # and override the default deployment info defined in type:Baseline
            v['type'] = DeploymentType.Embedded
            
            detection_name = info.data.get("name", None)
            if detection_name is None:
                raise ValueError("Could not create inline deployment - Baseline or Detection lacking 'name' field,")

            # Add a number of static values            
            v.update({
              'name': f"{detection_name} - Inline Deployment",
              'id':uuid.uuid4(),
              'date': datetime.date.today(),
              'description': "Inline deployment created at runtime.",
              'author': "contentctl tool"
            })

            
            # This constructs a temporary in-memory deployment,
            # allowing the deployment to be easily defined in the 
            # detection on a per detection basis.
            return Deployment.model_validate(v)
                        
        else:
            return SecurityContentObject.getDeploymentFromType(info.data.get("type",None), info)
    
    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model= {
            "scheduling": self.scheduling.model_dump(),
            "tags": self.tags
        }

        #Combine fields from this model with fields from parent
        model.update(super_fields)
        
        alert_action_fields = self.alert_action.model_dump()
        model.update(alert_action_fields)

        del(model['references'])
        
        #return the model
        return model