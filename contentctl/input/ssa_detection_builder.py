import sys
import re
import os

from pydantic import ValidationError
from typing import List
from contentctl.input.yml_reader import YmlReader
from contentctl.objects.detection import Detection
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.macro import Macro
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.enrichments.splunk_app_enrichment import SplunkAppEnrichment
from contentctl.objects.ssa_detection import SSADetection
from contentctl.objects.constants import *
from contentctl.enrichments.attack_enrichment import AttackEnrichment

class SSADetectionBuilder():
    security_content_obj : SSADetection


    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)  
        self.security_content_obj = SSADetection.parse_obj(yml_dict)
        self.security_content_obj.source = os.path.split(os.path.dirname(self.security_content_obj.file_path))[-1]

    def addProvidingTechnologies(self) -> None:
        if self.security_content_obj:
            if 'Endpoint' in str(self.security_content_obj.search):
                self.security_content_obj.providing_technologies = ["Sysmon", "Microsoft Windows","Carbon Black Response","CrowdStrike Falcon", "Symantec Endpoint Protection"]
            if "`cloudtrail`" in str(self.security_content_obj.search):
                self.security_content_obj.providing_technologies = ["Amazon Web Services - Cloudtrail"]
            if '`wineventlog_security`' in self.security_content_obj.search or '`powershell`' in self.security_content_obj.search:
                self.security_content_obj.providing_technologies = ["Microsoft Windows"]
                    

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


    def addUnitTest(self) -> None:
        if self.security_content_obj:
            if self.security_content_obj.tests:
                self.security_content_obj.test = self.security_content_obj.tests[0]


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
    def addMitreAttackEnrichmentNew(self, attack_enrichment: AttackEnrichment) -> None:
        if self.security_content_obj and self.security_content_obj.tags.mitre_attack_id:
            self.security_content_obj.tags.mitre_attack_enrichments = []
            for mitre_attack_id in self.security_content_obj.tags.mitre_attack_id:
                enrichment_obj = attack_enrichment.getEnrichmentByMitreID(mitre_attack_id)
                if enrichment_obj is not None:
                    self.security_content_obj.tags.mitre_attack_enrichments.append(enrichment_obj)



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


    def addRBA(self) -> None:
        if self.security_content_obj:
            if self.security_content_obj.tags.risk_score >= 80:
                self.security_content_obj.tags.risk_severity = 'high'
            elif (self.security_content_obj.tags.risk_score >= 50 and self.security_content_obj.tags.risk_score <= 79):
                self.security_content_obj.tags.risk_severity = 'medium'
            else:
                self.security_content_obj.tags.risk_severity = 'low'


    def reset(self) -> None:
        self.security_content_obj = None


    def getObject(self) -> SSADetection:
        return self.security_content_obj
