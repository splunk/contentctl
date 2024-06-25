import os
import pathlib
from typing import List, Any

from contentctl.objects.enums import SecurityContentType
from contentctl.output.jinja_writer import JinjaWriter
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.detection import Detection
class SvgOutput():

    
    def get_badge_dict(self, name:str, total_detections:List[Detection], these_detections:List[Detection])->dict[str,Any]:
        obj:dict[str,Any] = {}
        obj['name'] = name

        if name == "Production":
            obj['color'] = "Green"
        elif name == "Detections":
            obj['color'] = "Green"
        elif name == "Experimental":
            obj['color'] = "Yellow"
        elif name == "Deprecated":
            obj['color'] = "Red"

        obj['count'] = len(total_detections)
        if obj['count'] == 0:
            obj['coverage'] = "NaN"
        else:
            obj['coverage'] = len(these_detections) / obj['count']
            obj['coverage'] = "{:.0%}".format(obj['coverage'])
        return obj
    
    def writeObjects(self, detections: List[Detection], output_path: pathlib.Path, type: SecurityContentType = None) -> None:
        
        

        total_dict:dict[str,Any] = self.get_badge_dict("Detections", detections, detections)
        production_dict:dict[str,Any] = self.get_badge_dict("% Production", detections, [detection for detection in detections if detection.status == DetectionStatus.production.value])
        #deprecated_dict = self.get_badge_dict("Deprecated", detections, [detection for detection in detections if detection.status == DetectionStatus.deprecated])
        #experimental_dict = self.get_badge_dict("Experimental", detections, [detection for detection in detections if detection.status == DetectionStatus.experimental])
        
        


        #Total number of detections
        JinjaWriter.writeObject('detection_count.j2', output_path /'detection_count.svg', total_dict)
        #JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'production_count.svg'), production_dict)
        #JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'deprecated_count.svg'), deprecated_dict)
        #JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'experimental_count.svg'), experimental_dict)

        #Percentage of detections that are production
        JinjaWriter.writeObject('detection_coverage.j2', output_path/'detection_coverage.svg', production_dict)
        #JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), deprecated_dict)
        #JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), experimental_dict)

