

from pydantic import BaseModel, validator, ValidationError

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.unit_test_test import UnitTestTest

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    tests: list[UnitTestTest]
    file_path: str
    