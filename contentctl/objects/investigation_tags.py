
from pydantic import BaseModel, validator, ValidationError, Field
from contentctl.objects.enums import SecurityContentInvestigationProductName, SecurityDomain
from contentctl.objects.story import Story

class InvestigationTags(BaseModel):
    analytic_story: list[Story] = Field(min_length=1)
    product: list[SecurityContentInvestigationProductName] = Field(...,min_length=1)
    required_fields: list[str] = Field(min_length=1)
    security_domain: SecurityDomain = ...