
from pydantic import BaseModel, Field
from contentctl.objects.enums import SecurityContentProductName
from typing import List


class BaselineTags(BaseModel):
    analytic_story: List
    deployments: List = None
    detections: List
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: List
    security_domain: str