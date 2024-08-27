from pydantic import BaseModel, Field
class Drilldown(BaseModel):
    name: str = Field(...,min_length=5)
    search: str = Field(..., description="The text of a drilldown search. This must be valid SPL." min_length=1)
    earliest_offset:str = "$info_min_time$"
    latest_offset:str = "$info_max_time$"