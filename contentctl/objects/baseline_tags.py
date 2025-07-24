from __future__ import annotations

from typing import Any, List, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_serializer,
)

from contentctl.objects.detection import Detection
from contentctl.objects.enums import SecurityContentProductName, SecurityDomain
from contentctl.objects.story import Story


class BaselineTags(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analytic_story: list[Story] = Field(...)
    # deployment: Deployment = Field('SET_IN_GET_DEPLOYMENT_FUNCTION')
    # TODO (#223): can we remove str from the possible types here?
    detections: List[Union[Detection, str]] = Field(...)
    product: List[SecurityContentProductName] = Field(..., min_length=1)
    security_domain: SecurityDomain = Field(...)

    @field_validator("analytic_story", mode="before")
    def getStories(cls, v: Any, info: ValidationInfo) -> List[Story]:
        return Story.mapNamesToSecurityContentObjects(
            v, info.context.get("output_dto", None)
        )

    @model_serializer
    def serialize_model(self):
        # All fields custom to this model
        model = {
            "analytic_story": [story.name for story in self.analytic_story],
            "detections": [
                detection.name
                for detection in self.detections
                if isinstance(detection, Detection)
            ],
            "product": self.product,
            "security_domain": self.security_domain,
            "deployments": None,
        }

        # return the model
        return model
