import abc
import string
import uuid
from typing import Literal
from datetime import datetime
from pydantic import BaseModel, validator, ValidationError
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.constants import *
from contentctl.objects.security_content_object import SecurityContentObject

class Drilldown(BaseModel):

    drilldown_name: str
    drilldown_search: str
    earliest: str 
    latest: str
    required_fields: list
    # scheduling: DeploymentScheduling = None
    # email: DeploymentEmail = None
    # notable: DeploymentNotable = None
    # rba: DeploymentRBA = None
    # slack: DeploymentSlack = None
    # phantom: DeploymentPhantom = None
    # tags: dict = None
    

    

