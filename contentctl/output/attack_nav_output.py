import os
from typing import List,Union
import pathlib

from contentctl.objects.detection import Detection
from contentctl.output.attack_nav_writer import AttackNavWriter


class AttackNavOutput():

    def writeObjects(self, detections: List[Detection], output_path: pathlib.Path) -> None:
        techniques:dict[str,dict[str,Union[List[str],int]]] = {}
        for detection in detections:
            for tactic in detection.tags.mitre_attack_id:
                if tactic not in techniques:
                    techniques[tactic] = {'score':0,'file_paths':[]}
                
                detection_url = f"https://github.com/splunk/security_content/blob/develop/detections/{detection.source}/{detection.file_path.name}"
                techniques[tactic]['score'] += 1
                techniques[tactic]['file_paths'].append(detection_url)
                
        '''
        for detection in objects:
            if detection.tags.mitre_attack_enrichments:
                for mitre_attack_enrichment in detection.tags.mitre_attack_enrichments:
                    if not mitre_attack_enrichment.mitre_attack_id in techniques:
                        techniques[mitre_attack_enrichment.mitre_attack_id] = {
                                'score': 1,
                                'file_paths': ['https://github.com/splunk/security_content/blob/develop/detections/' + detection.getSource() + '/' + self.convertNameToFileName(detection.name)]
                            }
                    else:
                        techniques[mitre_attack_enrichment.mitre_attack_id]['score'] = techniques[mitre_attack_enrichment.mitre_attack_id]['score'] + 1
                        techniques[mitre_attack_enrichment.mitre_attack_id]['file_paths'].append('https://github.com/splunk/security_content/blob/develop/detections/' + detection.getSource() + '/' + self.convertNameToFileName(detection.name))
        '''
        AttackNavWriter.writeAttackNavFile(techniques, output_path / 'coverage.json')
        

    def convertNameToFileName(self, name: str):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        file_name = file_name + '.yml'
        return file_name
