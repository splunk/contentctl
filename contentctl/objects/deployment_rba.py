

from pydantic import BaseModel


class DeploymentRBA(BaseModel):
    enabled: str