import uuid
import string
import requests
import time
import sys

from pydantic import BaseModel, validator, root_validator, Extra
from dataclasses import dataclass
from typing import Union
from datetime import datetime, timedelta


from contentctl.objects.abstract_security_content_objects.detection_abstract import Detection_Abstract
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.config import ConfigDetectionConfiguration
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.baseline import Baseline
from contentctl.objects.playbook import Playbook
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType


class Detection(Detection_Abstract):
    # Customization to the Detection Class go here.
    # You may add fields and/or validations

    # You may also experiment with removing fields
    # and/or validations,  or chagning validation(s).  
    # Please be aware that many defaults field(s) 
    # or validation(s) are required and removing or
    # them or modifying their behavior may cause
    # undefined issues with the contentctl tooling 
    # or output of the tooling. 
    pass