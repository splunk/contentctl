from pydantic import BaseModel, Field
class Drilldown(BaseModel):
    name: str = Field(...,min_length=5)
    search: str = Field(...,description= "The drilldown search. The drilldown MUST begin with the | character followed by a space.", pattern=r"^\|\s+.*")
    earliest_offset:str = "$info_min_time$"
    latest_offset:str = "$info_max_time$"