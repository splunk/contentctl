from pydantic import BaseModel, ConfigDict
from enum import StrEnum, IntEnum

class SomeString(StrEnum):
    one = "one"
    two = "TWO"

class SomeInt(IntEnum):
    one = 1
    two = 2

class WithUseEnum(BaseModel):
    ConfigDict(use_enum_values=True)
    strval: SomeString
    intval: SomeInt


class WithOutUseEnum(BaseModel):
    strval: SomeString
    intval: SomeInt

withObj = WithUseEnum.model_validate({"strval": "one", "intval": "2"})
withoutObj = WithOutUseEnum.model_validate({"strval": "one", "intval": "2"})


print("With tests")
print(withObj.strval)
print(withObj.strval.upper())
print(withObj.strval.value)
print(withObj.intval)
print(withObj.intval.value)
print(withObj.strval == SomeString.one)
print(withObj.strval == "ONE")
print(withObj.intval == SomeInt.two)
print(withObj.intval == 2)


print("Without tests")
print(withoutObj.strval)
print(withoutObj.strval.value)
print(withoutObj.intval)
print(withoutObj.intval.value)
print(withoutObj.strval == SomeString.one)
print(withoutObj.strval == "ONE")
print(withoutObj.intval == SomeInt.two)
print(withoutObj.intval == 2)