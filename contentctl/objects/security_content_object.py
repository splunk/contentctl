import abc
import string
import uuid
from datetime import datetime
from pydantic import BaseModel, validator, ValidationError
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import SecurityContentObject_Abstract

class SecurityContentObject(SecurityContentObject_Abstract):
    pass