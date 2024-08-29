
from __future__ import annotations
import csv
import os
import sys
from attackcti import attack_client
import logging
from pydantic import BaseModel, Field
from dataclasses import field
from typing import Annotated,Any
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.config import validate
from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)


class AttackEnrichment(BaseModel):
    data: dict[str, MitreAttackEnrichment] = field(default_factory=dict)
    use_enrichment:bool = True
    
    @staticmethod
    def getAttackEnrichment(config:validate)->AttackEnrichment:
        enrichment = AttackEnrichment(use_enrichment=config.enrichments)
        _ = enrichment.get_attack_lookup(str(config.path))
        return enrichment
    
    def getEnrichmentByMitreID(self, mitre_id:MITRE_ATTACK_ID_TYPE)->MitreAttackEnrichment:
        if not self.use_enrichment:
            raise Exception(f"Error, trying to add Mitre Enrichment, but use_enrichment was set to False")
        
        enrichment = self.data.get(mitre_id, None)
        if enrichment is not None:
            return enrichment
        else:
            raise Exception(f"Error, Unable to find Mitre Enrichment for MitreID {mitre_id}")
        
    def addMitreIDViaGroupNames(self, technique:dict, tactics:list[str], groupNames:list[str])->None:
        technique_id = technique['technique_id']
        technique_obj = technique['technique']
        tactics.sort()
        
        if technique_id in self.data:
            raise Exception(f"Error, trying to redefine MITRE ID '{technique_id}'")
        self.data[technique_id] = MitreAttackEnrichment(mitre_attack_id=technique_id, 
                                                        mitre_attack_technique=technique_obj, 
                                                        mitre_attack_tactics=tactics, 
                                                        mitre_attack_groups=groupNames,
                                                        mitre_attack_group_objects=[]) 

    def addMitreIDViaGroupObjects(self, technique:dict, tactics:list[str],  groupObjects:list[dict[str,Any]])->None:
        technique_id = technique['technique_id']
        technique_obj = technique['technique']
        tactics.sort()
        
        groupNames:list[str] = sorted([group['group'] for group in groupObjects])
        
        if technique_id in self.data:
            raise Exception(f"Error, trying to redefine MITRE ID '{technique_id}'")
        self.data[technique_id] = MitreAttackEnrichment(mitre_attack_id=technique_id, 
                                                        mitre_attack_technique=technique_obj, 
                                                        mitre_attack_tactics=tactics, 
                                                        mitre_attack_groups=groupNames,
                                                        mitre_attack_group_objects=groupObjects)

    
    def get_attack_lookup(self, input_path: str, store_csv: bool = False, force_cached_or_offline: bool = False, skip_enrichment:bool = False) -> dict:
        if not self.use_enrichment:
            return {}
        print("Getting MITRE Attack Enrichment Data. This may take some time...")
        attack_lookup = dict()
        file_path = os.path.join(input_path, "app_template", "lookups", "mitre_enrichment.csv")

        if skip_enrichment is True:
            print("Skipping enrichment")
            return attack_lookup
        try:

            if force_cached_or_offline is True:
                raise(Exception("WARNING - Using cached MITRE Attack Enrichment.  Attack Enrichment may be out of date. Only use this setting for offline environments and development purposes."))
            print(f"\r{'Client'.rjust(23)}: [{0:3.0f}%]...", end="", flush=True)
            lift = attack_client()
            print(f"\r{'Client'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Techniques'.rjust(23)}: [{0.0:3.0f}%]...", end="", flush=True)
            all_enterprise_techniques = lift.get_enterprise_techniques(stix_format=False)
            
            print(f"\r{'Techniques'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Relationships'.rjust(23)}: [{0.0:3.0f}%]...", end="", flush=True)
            enterprise_relationships = lift.get_enterprise_relationships(stix_format=False)
            print(f"\r{'Relationships'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Groups'.rjust(23)}: [{0:3.0f}%]...", end="", flush=True)
            enterprise_groups = lift.get_enterprise_groups(stix_format=False)
            print(f"\r{'Groups'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            
            for index, technique in enumerate(all_enterprise_techniques):
                progress_percent = ((index+1)/len(all_enterprise_techniques)) * 100
                if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()):
                    print(f"\r\t{'MITRE Technique Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
                apt_groups:list[dict[str,Any]] = []
                for relationship in enterprise_relationships:
                    if (relationship['target_object'] == technique['id']) and relationship['source_object'].startswith('intrusion-set'):
                        for group in enterprise_groups:
                            if relationship['source_object'] == group['id']:
                                apt_groups.append(group)
                                #apt_groups.append(group['group'])

                tactics = []
                if ('tactic' in technique):
                    for tactic in technique['tactic']:
                        tactics.append(tactic.replace('-',' ').title())

                self.addMitreIDViaGroupObjects(technique, tactics, apt_groups)
                attack_lookup[technique['technique_id']] = {'technique': technique['technique'], 'tactics': tactics, 'groups': apt_groups}

            if store_csv:
                f = open(file_path, 'w')
                writer = csv.writer(f)
                writer.writerow(['mitre_id', 'technique', 'tactics' ,'groups'])
                for key in attack_lookup.keys():
                    if len(attack_lookup[key]['groups']) == 0:
                        groups = 'no'
                    else:
                        groups = '|'.join(attack_lookup[key]['groups'])
                    
                    writer.writerow([
                        key,
                        attack_lookup[key]['technique'],
                        '|'.join(attack_lookup[key]['tactics']),
                        groups
                    ])
                
                f.close()

        except Exception as err:
            print(f'\nError: {str(err)}')
            print('Use local copy app_template/lookups/mitre_enrichment.csv')
            with open(file_path, mode='r') as inp:
                reader = csv.reader(inp)
                attack_lookup = {rows[0]:{'technique': rows[1], 'tactics': rows[2].split('|'), 'groups': rows[3].split('|')} for rows in reader}
            attack_lookup.pop('mitre_id')
            for key in attack_lookup.keys():
                technique_input = {'technique_id': key , 'technique': attack_lookup[key]['technique'] }
                tactics_input = attack_lookup[key]['tactics']
                groups_input = attack_lookup[key]['groups']
                self.addMitreIDViaGroupNames(technique=technique_input, tactics=tactics_input, groups=groups_input)
            
                

        print("Done!")
        return attack_lookup