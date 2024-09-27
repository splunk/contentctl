from __future__ import annotations
from pydantic import BaseModel, Field
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection
from contentctl.objects.enums import AnalyticsType
SEARCH_PLACEHOLDER = "%original_detection_search%"
EARLIEST_OFFSET = "$info_min_time$"
LATEST_OFFSET = "$info_max_time$"
RISK_SEARCH = "index = risk | stats count values(search_name) values(risk_message) values(analyticstories) values(annotations._all) values(annotations.mitre_attack.mitre_tactic) by risk_object"

class Drilldown(BaseModel):
    name: str = Field(..., description="The name of the drilldown search", min_length=5)
    search: str = Field(..., description="The text of a drilldown search. This must be valid SPL.", min_length=1)
    earliest_offset:str = Field(..., 
                                description="Earliest offset time for the drilldown search. "
                                f"The most common value for this field is '{EARLIEST_OFFSET}', "
                                "but it is NOT the default value and must be supplied explicitly.", 
                                min_length= 1)
    latest_offset:str = Field(..., 
                              description="Latest offset time for the driolldown search. "
                              f"The most common value for this field is '{LATEST_OFFSET}', "
                              "but it is NOT the default value and must be supplied explicitly.", 
                              min_length= 1)

    @classmethod
    def constructDrilldownsFromDetection(cls, detection: Detection) -> list[Drilldown]:
        victim_observables = [o for o in detection.tags.observable if o.role[0] == "Victim"] 
        if len(victim_observables) == 0 or detection.type == AnalyticsType.Hunting:
            # No victims, so no drilldowns
            return []

        variableNamesString = ' and '.join([f"${o.name}$" for o in victim_observables])
        nameField = f"View the detection results for {variableNamesString}"
        appendedSearch =  " | search " + ' '.join([f"{o.name} = ${o.name}$" for o in victim_observables])
        search_field = f"{detection.search}{appendedSearch}"
        detection_results = cls(name=nameField, earliest_offset=EARLIEST_OFFSET, latest_offset=LATEST_OFFSET, search=search_field)
        
        
        nameField = f"View risk events for the last 7 days for {variableNamesString}"
        search_field = f"{RISK_SEARCH}{appendedSearch}"
        risk_events_last_7_days = cls(name=nameField, earliest_offset=EARLIEST_OFFSET, latest_offset=LATEST_OFFSET, search=search_field)

        return [detection_results,risk_events_last_7_days]
    

    def perform_search_substitutions(self, detection:Detection)->None:
        if (self.search.count("%") % 2) or (self.search.count("$") % 2):
            print("\n\nWarning - a non-even number of '%' or '$' characters were found in the\n"
                  f"drilldown search '{self.search}' for Detection {detection.file_path}.\n"
                  "If this was intentional, then please ignore this warning.\n")
        self.search = self.search.replace(SEARCH_PLACEHOLDER, detection.search)
    