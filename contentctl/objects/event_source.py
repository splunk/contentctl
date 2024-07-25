from __future__ import annotations
from typing import Union, Optional, List
from pydantic import BaseModel, Field

from contentctl.objects.security_content_object import SecurityContentObject

class EventSource(SecurityContentObject):
    fields: Optional[list[str]] = None
    field_mappings: Optional[list[dict]] = None
    convert_to_log_source: Optional[list[dict]] = None
    example_log: Optional[str] = None
