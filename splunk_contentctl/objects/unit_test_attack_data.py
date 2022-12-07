

from pydantic import BaseModel, validator, ValidationError
from splunk_contentctl.helper.utils import Utils
DEFAULT_INDEX = "main"
class UnitTestAttackData(BaseModel):
    file_name: str
    data: str
    source: str
    sourcetype: str
    update_timestamp: bool = False
    custom_index:str = DEFAULT_INDEX

    @validator('data', always=True)
    def validate_data(cls, v, values):
        return v
        try:
            Utils.verify_file_exists(v)
        except Exception as e:
            raise(ValueError(f"Cannot find file {v}: {str(e)}"))
        return v