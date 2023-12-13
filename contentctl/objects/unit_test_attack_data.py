from pydantic import BaseModel, HttpUrl, FilePath
from typing import Union, Optional


class UnitTestAttackData(BaseModel):
    data: Union[HttpUrl, FilePath] = ...
    # TODO - should source and sourcetype should be mapped to a list
    # of supported source and sourcetypes in a given environment?
    source: str = ...
    sourcetype: str = ...
    custom_index: Optional[str] = None
    host: Optional[str] = None