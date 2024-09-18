from __future__ import annotations
from pydantic import BaseModel, Field
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection
from contentctl.objects.enums import AnalyticsType
SEARCH_PLACEHOLDER = "%original_detection_search%"

class Drilldown(BaseModel):
    name: str = Field(..., description="The name of the drilldown search", min_length=5)
    search: str = Field(..., description="The text of a drilldown search. This must be valid SPL.", min_length=1)
    earliest_offset:str = Field(default="$info_min_time$", description="Earliest offset time for the drilldown search", min_length= 1)
    latest_offset:str = Field(default="$info_max_time$", description="Latest offset time for the driolldown search", min_length= 1)

    @classmethod
    def constructDrilldownFromDetection(cls, detection: Detection) -> Drilldown:
        if len([f"${o.name}$" for o in detection.tags.observable if o.role[0] == "Victim"]) == 0 and detection.type != AnalyticsType.Hunting:
            print("no victim!")
            # print(detection.tags.observable)
            # print(detection.file_path)
        name_field = "View the detection results for " + ' and ' + ''.join([f"${o.name}$" for o in detection.tags.observable if o.type[0] == "Victim"])
        search_field = f"{detection.search} | search " + ' '.join([f"o.name = ${o.name}$" for o in detection.tags.observable])
        return cls(name=name_field, search=search_field)
    

    def perform_search_substitutions(self, detection:Detection)->None:
        if (self.search.count("%") % 2) or (self.search.count("$") % 2):
            print("\n\nWarning - a non-even number of '%' or '$' characters were found in the\n"
                  f"drilldown search '{self.search}' for Detection {detection.file_path}.\n"
                  "If this was intentional, then please ignore this warning.\n")
        self.search = self.search.replace(SEARCH_PLACEHOLDER, detection.search)
    


