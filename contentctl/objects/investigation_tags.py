from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.story import Story
    


from pydantic import BaseModel, Field
from contentctl.objects.enums import SecurityContentInvestigationProductName, SecurityDomain


class InvestigationTags(BaseModel):
    analytic_story: list[Story] = Field([],min_length=1)
    product: list[SecurityContentInvestigationProductName] = Field(...,min_length=1)
    required_fields: list[str] = Field(min_length=1)
    security_domain: SecurityDomain = Field(...)