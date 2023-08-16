from contentctl.input.director import DirectorOutputDto
from dataclasses import dataclass
import streamlit as st

import contentctl
from contentctl.objects.detection import Detection
from contentctl.objects.security_content_object import SecurityContentObject


from contentctl.objects.enums import SecurityContentType
from contentctl.objects.enums import AnalyticsType
import datetime
from contentctl.objects.enums import DetectionStatus
import pandas as pd

@dataclass(frozen=True)
class WebUIInputDto:
    director_output_dto: DirectorOutputDto


class WebUI:
    def execute(self, input:WebUIInputDto) -> None:
        st.title("Welcome to the contentctl Web UI")

        import json
        content_as_dict = [json.loads(d.json()) for d in input.director_output_dto.detections]
        '''
        d = {}
        for m in content_as_dict:
            import json
            import code
            #code.interact(local=locals())
            j = json.loads(m)
            d[j['name']] = j
        '''
        df = pd.DataFrame(content_as_dict)
        print(df)
        #import code
        #code.interact(local=locals())
        st.table(df)

        '''
        detection:Detection = st.selectbox("Choose a Detection", input.director_output_dto.detections, format_func=lambda x: x.name)
        
        o = detection
        # for field in detection.__fields__:
        #     fieldObject = detection.__fields__[field]
        #     print(fieldObject.type_)
        #     st.text_input(field, value=detection.__getattribute__(field))
        #o = SecurityContentObject(contentType=SecurityContentType.detections, date = datetime.date.today())
        
        all_fields = {}
        all_fields['name'] = st.text_input("name",value=o.name)
        all_fields['author'] = st.text_input("author",value=o.author)
        all_fields['date'] = st.text_input("date",value=o.date,disabled=True)
        all_fields['version'] = st.text_input("version",value=o.version, disabled=True)
        all_fields['id'] = st.text_input("id",value=o.id, disabled=True)
        all_fields['description'] = st.text_input("description",value=o.description)
        #all_fields['file_path'] = st.text_input("file_path",value=o.)

        all_fields['type'] = st.selectbox("type", AnalyticsType,format_func=lambda x: x.name)
        all_fields['status'] = st.selectbox("status", DetectionStatus, format_func=lambda x: x.name)

        all_fields['data_source'] = st.multiselect("data_source", ["Sysmon1", "Sysmon2"])
        all_fields['tags'] = st.text_input("tags",value={})
        all_fields['search'] = st.text_input("search",value="INPUT SPL HERE",)
        all_fields['how_to_implement'] = st.text_input("how_to_implement",value="DESCRIBE HOW TO IMPLEMENT THE SEARCH")
        all_fields['known_false_positive'] = st.text_input("known_false_positives",value="DESCRIBE KNOWN FALSE POSITIVES")
        all_fields['references'] = st.text_input("references",value="")
        '''     


            