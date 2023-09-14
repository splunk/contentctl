from pydantic import BaseModel, validator, ValidationError


from contentctl.objects.unit_test import UnitTest


class UnitTestOld(BaseModel):
    name: str
    tests: list[UnitTest]