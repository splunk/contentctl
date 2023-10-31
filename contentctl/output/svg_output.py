import os
import pathlib

from contentctl.objects.enums import SecurityContentType
from contentctl.output.jinja_writer import JinjaWriter
from contentctl.objects.config import Config
from contentctl.objects.enums import DetectionStatus
class SvgOutput():

    def writeObjects(self, objects: list, path: str, type: SecurityContentType = None) -> None:
        
        detections_tmp = objects    

        output_path = pathlib.Path(path)

        tested_detections = []
        untested_detections = []
        obj = dict()
        
        for detection in detections_tmp:
            if detection.status == DetectionStatus.production.value:
                tested_detections.append(detection)
            else: 
                untested_detections.append(detection)

        
        obj['count'] = len(tested_detections) + len(untested_detections)
        if obj['count'] == 0:
            obj['coverage'] = "NaN"
        else:
            obj['coverage'] = len(tested_detections) / obj['count']
            obj['coverage'] = "{:.0%}".format(obj['coverage'])

        JinjaWriter.writeObject('detection_count.j2', os.path.join(output_path, 'detection_count.svg'), obj)
        JinjaWriter.writeObject('detection_coverage.j2', os.path.join(output_path, 'detection_coverage.svg'), obj)

