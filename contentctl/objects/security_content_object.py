import abc

from contentctl.objects.enums import SecurityContentType


class SecurityContentObject(abc.ABC):
    type: SecurityContentType
