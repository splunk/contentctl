from pydantic import BaseModel, Field, field_validator
from typing import Annotated


# Alert Suppression/Throttling settings have been taken from 
# https://docs.splunk.com/Documentation/Splunk/9.2.2/Admin/Savedsearchesconf
class Throttling(BaseModel):
    fields: list[str] = Field(..., description="The list of fields to throttle on. These fields MUST occur in the search.", min_length=1)
    period: Annotated[str,Field(pattern="^[0-9]+[smh]$")] =  Field(..., description="How often the alert should be triggered. "
                                                    "This may be specified in seconds, minutes, or hours.  "
                                                    "For example, if an alert should be triggered once a day,"
                                                    " it may be specified in seconds (86400s), minutes (1440m), or hours import (24h).")
    
    @field_validator("fields")
    def no_spaces_in_fields(cls, v:list[str])->list[str]:
        for field in v:
            if ' ' in field:
                raise ValueError("Spaces are not presently supported in 'alert.suppress.fields' / throttling fields in conf files. "
                                "The field '{field}' has a space in it. If this is a blocker, please raise this as an issue on the Project.")
        return v

    def conf_formatted_fields(self)->str:
        '''
        TODO:
        The field alert.suppress.fields is defined as follows:
        alert.suppress.fields = <comma-delimited-field-list>
        * List of fields to use when suppressing per-result alerts. This field *must*
        be specified if the digest mode is disabled and suppression is enabled.

        In order to support fields with spaces in them, we may need to wrap each
        field in "". 
        This function returns a properly formatted value, where each field
        is wrapped in "" and separated with a comma. For example, the fields 
        ["field1", "field 2", "field3"] would be returned as the string

        "field1","field 2","field3

        However, for now, we will error on fields with spaces and simply
        separate with commas
        '''
        
        return ",".join(self.fields)

        # The following may be used once we determine proper support
        # for fields with spaces
        #return ",".join([f'"{field}"' for field in self.fields])