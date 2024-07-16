from pydantic import BaseModel, Field
from typing import Annotated

# MAximum throttling window defined as once per day.
MAX_THROTTLING_WINDOW = 60 * 60 * 24

# Alert Suppression/Throttling settings have been taken from 
# https://docs.splunk.com/Documentation/Splunk/9.2.2/Admin/Savedsearchesconf
class AlertSuppression(BaseModel):
    fields: list[str] = Field(..., description="The list of fields to throttle on. These fields MUST occur in the search.", min_length=1)
    period: Annotated[str,Field(pattern="^[0-9]+[smh]$")] =  Field(..., description="How often the alert should be triggered. "
                                                    "This may be specified in seconds, minutes, or hours.  "
                                                    "For example, if an alert should be triggered once a day,"
                                                    " it may be specified in seconds (86400s), minutes (1440m), or hours import (24h).")
    
    

    def conf_formatted_fields(self)->str:
        '''
        The field alert.suppress.fields is defined as follows:
        alert.suppress.fields = <comma-delimited-field-list>
        * List of fields to use when suppressing per-result alerts. This field *must*
        be specified if the digest mode is disabled and suppression is enabled.

        In order to support fields with spaces in them, we must also wrap each
        field in "". 
        This function returns a properly formatted value, where each field
        is wrapped in "" and separated with a comma. For example, the fields 
        ["field1", "field 2", "field3"] would be returned as the string

        "field1","field 2","field3
        '''
        return ",".join([f'"{field}"' for field in self.fields])