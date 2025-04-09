from __future__ import annotations

from abc import ABC

from pydantic import BaseModel


class EmailObject(BaseModel, ABC):
    to: str
    subject: str
    message: str
