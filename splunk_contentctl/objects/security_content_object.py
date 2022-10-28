import abc

from objects.enums import SecurityContentType


class SecurityContentObject(abc.ABC):
    type: SecurityContentType
