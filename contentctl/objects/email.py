from __future__ import annotations

from abc import ABC
from typing import Any

from pydantic import BaseModel, model_validator


class EmailObject(BaseModel, ABC):
    to: str
    subject: str
    message: str

    @model_validator(mode="before")
    # Validate the email address
    def validate_email(cls, data: str) -> str:
        if data.get("to"):
            if "@" not in data.get("to"):
                raise ValueError("Invalid email address")
            return data
