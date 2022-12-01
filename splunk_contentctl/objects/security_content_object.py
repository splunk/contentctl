import abc

from splunk_contentctl.objects.enums import SecurityContentType


class SecurityContentObject(abc.ABC):
    type: SecurityContentType
