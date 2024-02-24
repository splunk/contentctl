import abc
import string
import uuid
from typing import Literal
from datetime import datetime
from pydantic import BaseModel, validator, ValidationError
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.constants import *

class Drilldowns(BaseModel):

    drilldown_name: str
    drilldown_search: str


    

