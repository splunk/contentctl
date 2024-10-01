from __future__ import annotations
from pydantic import BaseModel, Field, model_serializer
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection
from contentctl.objects.enums import AnalyticsType
DRILLDOWN_SEARCH_PLACEHOLDER = "%original_detection_search%"
EARLIEST_OFFSET = "$info_min_time$"
LATEST_OFFSET = "$info_max_time$"
RISK_SEARCH = "index = risk  starthoursago = 168 endhoursago = 0 | stats count values(search_name) values(risk_message) values(analyticstories) values(annotations._all) values(annotations.mitre_attack.mitre_tactic) "

class Drilldown(BaseModel):
    name: str = Field(..., description="The name of the drilldown search", min_length=5)
    search: str = Field(..., description="The text of a drilldown search. This must be valid SPL.", min_length=1)
    earliest_offset:None | str = Field(..., 
                                description="Earliest offset time for the drilldown search. "
                                f"The most common value for this field is '{EARLIEST_OFFSET}', "
                                "but it is NOT the default value and must be supplied explicitly.", 
                                min_length= 1)
    latest_offset:None | str = Field(..., 
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
        print(f"Adding default drilldowns for [{detection.name}]")
        variableNamesString = ' and '.join([f"${o.name}$" for o in victim_observables])
        nameField = f"View the detection results for {variableNamesString}"
        appendedSearch =  " | search " + ' '.join([f"{o.name} = ${o.name}$" for o in victim_observables])
        search_field = f"{detection.search}{appendedSearch}"
        detection_results = cls(name=nameField, earliest_offset=EARLIEST_OFFSET, latest_offset=LATEST_OFFSET, search=search_field)
        
        
        nameField = f"View risk events for the last 7 days for {variableNamesString}"
        fieldNamesListString = ', '.join([o.name for o in victim_observables])
        search_field = f"{RISK_SEARCH}by {fieldNamesListString} {appendedSearch}"
        risk_events_last_7_days = cls(name=nameField, earliest_offset=None, latest_offset=None, search=search_field)

        return [detection_results,risk_events_last_7_days]
    

    def perform_search_substitutions(self, detection:Detection)->None:
        """Replaces the field DRILLDOWN_SEARCH_PLACEHOLDER (%original_detection_search%)
        with the search contained in the detection. We do this so that the YML does not
        need the search copy/pasted from the search field into the drilldown object.

        Args:
            detection (Detection): Detection to be used to update the search field of the drilldown
        """             
        self.search = self.search.replace(DRILLDOWN_SEARCH_PLACEHOLDER, detection.search)
    

    @model_serializer
    def serialize_model(self) -> dict[str,str]:
        #Call serializer for parent
        model:dict[str,str] = {}

        model['name'] = self.name
        model['search'] = self.search
        if self.earliest_offset is not None:
            model['earliest_offset'] = self.earliest_offset
        if self.latest_offset is not None:
            model['latest_offset'] = self.latest_offset
        return model