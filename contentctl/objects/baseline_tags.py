
from pydantic import BaseModel, validator, ValidationError, Field
from contentctl.objects.enums import SecurityContentProductName
from typing import List, Optional


class BaselineTags(BaseModel):
    analytic_story: List
    deployments: List = None
    detections: List
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: List
    security_domain: str