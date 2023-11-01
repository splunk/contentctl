import os
import pathlib

from contentctl.objects.enums import SecurityContentType
from contentctl.output.jinja_writer import JinjaWriter
from contentctl.objects.config import Config
from contentctl.objects.enums import DetectionStatus
class SvgOutput():

    def get_badge_dict(self, name:str, total_detections:list, these_detections:list):
        obj = dict()
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

    def writeObjects(self, objects: list, path: str, type: SecurityContentType = None) -> None:
        
        detections_tmp = objects    

        output_path = pathlib.Path(path)

        production_detections = []
        deprecated_detections = []
        experimental_detections = []
        obj = dict()
        
        for detection in detections_tmp:
            if detection.status == DetectionStatus.production.value:
                production_detections.append(detection)
            if detection.status == DetectionStatus.deprecated.value:
                deprecated_detections.append(detection)
            elif detection.status == DetectionStatus.experimental.value:
                experimental_detections.append(detection)

        
        total_detections = production_detections + deprecated_detections + experimental_detections
        total_dict = self.get_badge_dict("Detections", total_detections, production_detections)
        production_dict = self.get_badge_dict("Production", total_detections, production_detections)
        deprecated_dict = self.get_badge_dict("Deprecated", total_detections, deprecated_detections)
        experimental_dict = self.get_badge_dict("Experimental", total_detections, experimental_detections)
        

        JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'detection_count.svg'), total_dict)
        #JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'production_count.svg'), production_dict)
        #JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'deprecated_count.svg'), deprecated_dict)
        #JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'experimental_count.svg'), experimental_dict)

        JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), total_dict)
        #JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), deprecated_dict)
        #JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), experimental_dict)

