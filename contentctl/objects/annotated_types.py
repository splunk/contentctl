from typing import Annotated

from pydantic import Field

CVE_TYPE = Annotated[str, Field(pattern=r"^CVE-[1|2]\d{3}-\d+$")]
MITRE_ATTACK_ID_TYPE_PARENT = Annotated[str, Field(pattern=r"^T\d{4}$")]
MITRE_ATTACK_ID_TYPE_SUBTYPE = Annotated[str, Field(pattern=r"^T\d{4}(.\d{3})$")]
MITRE_ATTACK_ID_TYPE = MITRE_ATTACK_ID_TYPE_PARENT | MITRE_ATTACK_ID_TYPE_SUBTYPE
APPID_TYPE = Annotated[str, Field(pattern="^[a-zA-Z0-9_-]+$")]
