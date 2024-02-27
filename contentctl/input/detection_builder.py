import sys
import re
import os


from contentctl.input.yml_reader import YmlReader
from contentctl.objects.detection import Detection
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.enrichments.splunk_app_enrichment import SplunkAppEnrichment
from contentctl.objects.enums import RiskSeverity, ProvidingTechnology

from contentctl.helper.constants import *


from contentctl.input.director import DirectorOutputDto
from typing import Union
class DetectionBuilder():
    security_content_obj : Detection


    def setObject(self, path: str, 
        output_dto:DirectorOutputDto) -> None:
        yml_dict = YmlReader.load_file(path)
        self.security_content_obj = Detection.model_validate(yml_dict, context={"output_dto":output_dto})
        

    def addRBA(self) -> None:
        if self.security_content_obj:

            risk_objects:list[dict[str,Union[str,int]]] = []
            risk_object_user_types = {'user', 'username', 'email address'}
            risk_object_system_types = {'device', 'endpoint', 'hostname', 'ip address'}

            if hasattr(self.security_content_obj.tags, 'observable') and hasattr(self.security_content_obj.tags, 'risk_score'):
                for entity in self.security_content_obj.tags.observable or []:

                    risk_object:dict[str,Union[str,int]] = dict()
                    if entity.type.lower() in risk_object_user_types:
                        risk_object['risk_object_type'] = 'user'
                        risk_object['risk_object_field'] = entity.name
                        risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                        risk_objects.append(risk_object)

                    elif entity.type.lower() in risk_object_system_types:
                        risk_object['risk_object_type'] = 'system'
                        risk_object['risk_object_field'] = entity.name
                        risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                        risk_objects.append(risk_object)

                    elif 'Attacker' in entity.role:
                        risk_object['threat_object_field'] = entity.name
                        risk_object['threat_object_type'] = entity.type.lower()
                        risk_objects.append(risk_object) 
                    else:
                        risk_object['risk_object_type'] = 'other'
                        risk_object['risk_object_field'] = entity.name
                        risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                        risk_objects.append(risk_object)
                        continue

            if self.security_content_obj.tags.risk_score >= 80:
                self.security_content_obj.tags.risk_severity = RiskSeverity.HIGH
            elif (self.security_content_obj.tags.risk_score >= 50 and self.security_content_obj.tags.risk_score <= 79):
                self.security_content_obj.tags.risk_severity = RiskSeverity.MEDIUM
            else:
                self.security_content_obj.tags.risk_severity = RiskSeverity.LOW

            self.security_content_obj.risk = risk_objects


    def addProvidingTechnologies(self) -> None:
        if self.security_content_obj:
            if 'Endpoint' in str(self.security_content_obj.search):
                self.security_content_obj.providing_technologies = [ProvidingTechnology.SYSMON, ProvidingTechnology.MICROSOFT_WINDOWS,ProvidingTechnology.CARBON_BLACK_RESPONSE,ProvidingTechnology.CROWDSTRIKE_FALCON, ProvidingTechnology.SYMANTEC_ENDPOINT_PROTECTION]
            if "`cloudtrail`" in str(self.security_content_obj.search):
                self.security_content_obj.providing_technologies = [ProvidingTechnology.AMAZON_WEB_SERVICES_CLOUDTRAIL]
            if '`wineventlog_security`' in self.security_content_obj.search or '`powershell`' in self.security_content_obj.search:
                self.security_content_obj.providing_technologies = [ProvidingTechnology.MICROSOFT_WINDOWS]

    
    def addNesFields(self) -> None:
        if self.security_content_obj:
            if self.security_content_obj.deployment:
                if self.security_content_obj.deployment.notable:
                    nes_fields = ",".join(list(self.security_content_obj.deployment.notable.nes_fields))
                    self.security_content_obj.nes_fields = nes_fields
                    

    def addMappings(self) -> None:
        if self.security_content_obj:
            keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist']
            mappings = {}
            for key in keys:
                if key == 'mitre_attack':
                    if getattr(self.security_content_obj.tags, 'mitre_attack_id'):
                        mappings[key] = getattr(self.security_content_obj.tags, 'mitre_attack_id')
                elif getattr(self.security_content_obj.tags, key):
                    mappings[key] = getattr(self.security_content_obj.tags, key)
            self.security_content_obj.mappings = mappings


    def addAnnotations(self) -> None:
        if self.security_content_obj:
            annotations = {}
            annotation_keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist', 
                'analytic_story', 'context', 'impact', 'confidence', 'cve']
            for key in annotation_keys:
                if key == 'mitre_attack':
                    if getattr(self.security_content_obj.tags, 'mitre_attack_id'):
                        annotations[key] = getattr(self.security_content_obj.tags, 'mitre_attack_id')
                try:
                    if getattr(self.security_content_obj.tags, key):
                        annotations[key] = getattr(self.security_content_obj.tags, key)
                except AttributeError as e:
                    continue
            self.security_content_obj.annotations = annotations    



    def addMitreAttackEnrichment(self, attack_enrichment: dict) -> None:
        if self.security_content_obj:
            if attack_enrichment:
                if self.security_content_obj.tags.mitre_attack_id:
                    self.security_content_obj.tags.mitre_attack_enrichments = []
                    
                    for mitre_attack_id in self.security_content_obj.tags.mitre_attack_id:
                        if mitre_attack_id in attack_enrichment:
                            mitre_attack_enrichment = MitreAttackEnrichment(
                                mitre_attack_id = mitre_attack_id, 
                                mitre_attack_technique = attack_enrichment[mitre_attack_id]["technique"], 
                                mitre_attack_tactics = sorted(attack_enrichment[mitre_attack_id]["tactics"]), 
                                mitre_attack_groups = sorted(attack_enrichment[mitre_attack_id]["groups"])
                            )
                            self.security_content_obj.tags.mitre_attack_enrichments.append(mitre_attack_enrichment)
                        else:
                            #print("mitre_attack_id " + mitre_attack_id + " doesn't exist for detecction " + self.security_content_obj.name)
                            raise ValueError("mitre_attack_id " + mitre_attack_id + " doesn't exist for detection " + self.security_content_obj.name)


    def addMacros(self, macros: list) -> None:
        if self.security_content_obj:
            found_macros =  Macro.get_macros(self.security_content_obj.search, macros)
            name = self.security_content_obj.name.replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
            macro = Macro(name=name, definition='search *', description='Update this macro to limit the output results to filter out false positives.')
            found_macros.append(macro)
            self.security_content_obj.macros = found_macros
            
                         

    def addCve(self) -> None:
        if self.security_content_obj:
            self.security_content_obj.cve_enrichment = []
            if self.security_content_obj.tags.cve:
                for cve in self.security_content_obj.tags.cve:
                    self.security_content_obj.cve_enrichment.append(CveEnrichment.enrich_cve(cve))


    def addSplunkApp(self) -> None:
        if self.security_content_obj:
            self.security_content_obj.splunk_app_enrichment = []
            if self.security_content_obj.tags.supported_tas:
                for splunk_app in self.security_content_obj.tags.supported_tas:
                    self.security_content_obj.splunk_app_enrichment.append(SplunkAppEnrichment.enrich_splunk_app(splunk_app))



    def reset(self) -> None:
        self.security_content_obj = None


    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj
