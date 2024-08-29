from pydantic import Field
from typing import Annotated

CVE_TYPE = Annotated[str, Field(pattern=r"^CVE-[1|2]\d{3}-\d+$")]
MITRE_ATTACK_ID_TYPE = Annotated[str, Field(pattern=r"^T\d{4}(.\d{3})?$")]
APPID_TYPE = Annotated[str,Field(pattern="^[a-zA-Z0-9_-]+$")]