from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field, HttpUrl, FilePath
import pathlib
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.unit_test_attack_data import UnitTestAttackData
    from contentctl.objects.unit_test_result import UnitTestResult

from typing import Union

from pydantic import Field, field_serializer

# from contentctl.objects.security_content_object import SecurityContentObject
# from contentctl.objects.enums import SecurityContentType
from contentctl.objects.unit_test_baseline import UnitTestBaseline
from contentctl.objects.unit_test_attack_data import UnitTestAttackData
from contentctl.objects.unit_test_result import UnitTestResult
from contentctl.objects.base_test import BaseTest, TestType
from contentctl.objects.base_test_result import TestResultStatus



class UnitTestAttackDataSSA(BaseModel):
    data: str = Field(...)
    # TODO - should source and sourcetype should be mapped to a list
    # of supported source and sourcetypes in a given environment?
    source: str = Field(...)

    sourcetype: Optional[str] = None


class UnitTestSSA(BaseModel):
    """
    A unit test for a detection
    """
    name: str

    # The attack data to be ingested for the unit test
    attack_data: list[UnitTestAttackDataSSA] = Field(...)





    

