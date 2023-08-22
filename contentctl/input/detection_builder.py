import json
import sys
import re
import os

from pydantic import ValidationError

from contentctl.input.yml_reader import YmlReader
from contentctl.objects.detection import Detection
from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.macro import Macro
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.enrichments.splunk_app_enrichment import SplunkAppEnrichment
from contentctl.objects.config import ConfigDetectionConfiguration


class DetectionBuilder():
    security_content_obj : SecurityContentObject


    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        yml_dict["tags"]["name"] = yml_dict["name"]
        self.security_content_obj = Detection.parse_obj(yml_dict)
        self.security_content_obj.source = os.path.split(os.path.dirname(self.security_content_obj.file_path))[-1]      

    def addNextSteps(self):
        if self.security_content_obj:
            tags: DetectionTags = self.security_content_obj.tags
            obj = {
                "version": 1,
                "data": tags.next_steps,
            }
            tags.next_steps = json.dumps(obj)

    def addDeployment(self, detection_configuration: ConfigDetectionConfiguration) -> None:
        if self.security_content_obj:
            self.security_content_obj.deployment = detection_configuration


    def addRBA(self) -> None:
        if self.security_content_obj:

            risk_objects = []
            risk_object_user_types = {'user', 'username', 'email address'}
            risk_object_system_types = {'device', 'endpoint', 'hostname', 'ip address'}

            if hasattr(self.security_content_obj.tags, 'observable') and hasattr(self.security_content_obj.tags, 'risk_score'):
                for entity in self.security_content_obj.tags.observable:

                    risk_object = dict()
                    if entity['type'].lower() in risk_object_user_types:
                        risk_object['risk_object_type'] = 'user'
                        risk_object['risk_object_field'] = entity['name']
                        risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                        risk_objects.append(risk_object)

                    elif entity['type'].lower() in risk_object_system_types:
                        risk_object['risk_object_type'] = 'system'
                        risk_object['risk_object_field'] = entity['name']
                        risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                        risk_objects.append(risk_object)

                    elif 'role' in entity and 'Attacker' in entity['role']:
                        risk_object['threat_object_field'] = entity['name']
                        risk_object['threat_object_type'] = entity['type'].lower()
                        risk_objects.append(risk_object) 
                    else:
                        risk_object['risk_object_type'] = 'other'
                        risk_object['risk_object_field'] = entity['name']
                        risk_object['risk_score'] = self.security_content_obj.tags.risk_score
                        risk_objects.append(risk_object)
                        continue

            if self.security_content_obj.tags.risk_score >= 80:
                self.security_content_obj.tags.risk_severity = 'high'
            elif (self.security_content_obj.tags.risk_score >= 50 and self.security_content_obj.tags.risk_score <= 79):
                self.security_content_obj.tags.risk_severity = 'medium'
            else:
                self.security_content_obj.tags.risk_severity = 'low'

            self.security_content_obj.risk = risk_objects


    def addProvidingTechnologies(self) -> None:
        if self.security_content_obj:
            if 'Endpoint' in str(self.security_content_obj.search):
                self.security_content_obj.providing_technologies = ["Sysmon", "Microsoft Windows","Carbon Black Response","CrowdStrike Falcon", "Symantec Endpoint Protection"]
            if "`cloudtrail`" in str(self.security_content_obj.search):
                self.security_content_obj.providing_technologies = ["Amazon Web Services - Cloudtrail"]
            if '`wineventlog_security`' in self.security_content_obj.search or '`powershell`' in self.security_content_obj.search:
                self.security_content_obj.providing_technologies = ["Microsoft Windows"]

    
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


    def addPlaybook(self, playbooks: list) -> None:
        if self.security_content_obj:
            matched_playbooks = []
            for playbook in playbooks:
                if playbook.tags.detections:
                    for detection in playbook.tags.detections:
                        if detection == self.security_content_obj.name:
                            matched_playbooks.append(playbook)

            self.security_content_obj.playbooks = matched_playbooks


    def addBaseline(self, baselines: list) -> None:
        if self.security_content_obj:
            matched_baselines = []
            for baseline in baselines:
                for detection in baseline.tags.detections:
                    if detection == self.security_content_obj.name:
                        matched_baselines.append(baseline)

            self.security_content_obj.baselines = matched_baselines


    def addUnitTest(self, tests: list) -> None:
        if self.security_content_obj:
            if self.security_content_obj.tests and len(self.security_content_obj.tests) > 0: 
                return
            elif self.security_content_obj.type not in ["Correlation"] and \
               self.security_content_obj.deprecated == False and \
               self.security_content_obj.experimental == False and \
               self.security_content_obj.tags.manual_test == None:
                raise(Exception(f"No tests found found {self.security_content_obj.file_path}"))
                #print(f"No tests found found {self.security_content_obj.file_path}")
            return None



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
            macros_found = re.findall(r'`([^\s]+)`', self.security_content_obj.search)
            macros_filtered = set()
            self.security_content_obj.macros = []

            for macro in macros_found:
                if not '_filter' in macro and not 'drop_dm_object_name' in macro:
                    start = macro.find('(')
                    if start != -1:
                        macros_filtered.add(macro[:start])
                    else:
                        macros_filtered.add(macro)

            for macro_name in macros_filtered:
                for macro in macros:
                    if macro_name == macro.name:
                        self.security_content_obj.macros.append(macro)

            name = self.security_content_obj.name.replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
            macro = Macro(name=name, definition='search *', description='Update this macro to limit the output results to filter out false positives.')
            
            self.security_content_obj.macros.append(macro)


    def addLookups(self, lookups: list) -> None:
        if self.security_content_obj:
            lookups_found = re.findall(r'lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', self.security_content_obj.search)
            self.security_content_obj.lookups = []
            for lookup_name in lookups_found:
                for lookup in lookups:
                    if lookup.name == lookup_name:
                        self.security_content_obj.lookups.append(lookup)


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

    def addCIS(self) -> None:
        if self.security_content_obj:
            if self.security_content_obj.tags.security_domain == "network":
                self.security_content_obj.tags.cis20 = ["CIS 13"]
            else:
                self.security_content_obj.tags.cis20 = ["CIS 10"]


    def addKillChainPhase(self) -> None:
        if self.security_content_obj:
            if not self.security_content_obj.tags.kill_chain_phases:
                kill_chain_phases = list()
                if self.security_content_obj.tags.mitre_attack_enrichments:
                    for mitre_attack_enrichment in self.security_content_obj.tags.mitre_attack_enrichments:
                        for mitre_attack_tactic in mitre_attack_enrichment.mitre_attack_tactics:
                            kill_chain_phases.append(ATTACK_TACTICS_KILLCHAIN_MAPPING[mitre_attack_tactic])
                self.security_content_obj.tags.kill_chain_phases = list(dict.fromkeys(kill_chain_phases))

    def addNist(self) -> None:
        if self.security_content_obj:
            if self.security_content_obj.type == "TTP":
                self.security_content_obj.tags.nist = ["DE.CM"]
            else:
                self.security_content_obj.tags.nist = ["DE.AE"]

    def addDatamodel(self) -> None:
        if self.security_content_obj:
            self.security_content_obj.datamodel = []
            data_models = [
                "Authentication", 
                "Change", 
                "Change_Analysis", 
                "Email", 
                "Endpoint", 
                "Network_Resolution", 
                "Network_Sessions", 
                "Network_Traffic", 
                "Risk", 
                "Splunk_Audit", 
                "UEBA", 
                "Updates", 
                "Vulnerabilities", 
                "Web"
            ]
            for data_model in data_models:
                if data_model in self.security_content_obj.search:
                    self.security_content_obj.datamodel.append(data_model)


    def reset(self) -> None:
        self.security_content_obj = None


    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj
