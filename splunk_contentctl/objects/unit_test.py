

from pydantic import BaseModel, validator, ValidationError

from objects.security_content_object import SecurityContentObject
from objects.unit_test_test import UnitTestTest

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    tests: list[UnitTestTest]
    