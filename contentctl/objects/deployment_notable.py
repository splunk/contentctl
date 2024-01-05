
from pydantic import BaseModel


class DeploymentNotable(BaseModel):
    rule_description: str
    rule_title: str
    nes_fields: list[str]