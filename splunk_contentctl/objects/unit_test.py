

from pydantic import BaseModel, validator, ValidationError

from splunk_contentctl.objects.security_content_object import SecurityContentObject
from splunk_contentctl.objects.unit_test_test import UnitTestTest

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    tests: list[UnitTestTest]
    