import abc

from bin.objects.enums import SecurityContentType


class SecurityContentObject(abc.ABC):
    type: SecurityContentType
