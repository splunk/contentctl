
from __future__ import annotations
import csv
import os
from posixpath import split
from typing import Optional
import sys
from attackcti import attack_client
import logging
from pydantic import BaseModel, Field
from dataclasses import field
from typing import Union,Annotated
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.config import validate
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)


class AttackEnrichment(BaseModel):
    data: dict[str, MitreAttackEnrichment] = field(default_factory=dict)
    use_enrichment:bool = True
    
    @staticmethod
    def getAttackEnrichment(config:validate)->AttackEnrichment:
        enrichment = AttackEnrichment(use_enrichment=config.enrichments)
        _ = enrichment.get_attack_lookup(str(config.path))
        return enrichment
    
    def getEnrichmentByMitreID(self, mitre_id:Annotated[str, Field(pattern="^T\d{4}(.\d{3})?$")])->Union[MitreAttackEnrichment,None]:
        if not self.use_enrichment:
            return None
        
        enrichment = self.data.get(mitre_id, None)
        if enrichment is not None:
            return enrichment
        else:
            raise ValueError(f"Error, Unable to find Mitre Enrichment for MitreID {mitre_id}")
        

    def addMitreID(self, technique:dict, tactics:list[str], groups:list[str])->None:
        
        technique_id = technique['technique_id']
        technique_obj = technique['technique']
        tactics.sort()
        groups.sort()

        if technique_id in self.data:
            raise ValueError(f"Error, trying to redefine MITRE ID '{technique_id}'")
        
        self.data[technique_id] = MitreAttackEnrichment(mitre_attack_id=technique_id, 
                                                        mitre_attack_technique=technique_obj, 
                                                        mitre_attack_tactics=tactics, 
                                                        mitre_attack_groups=groups)

    
    def get_attack_lookup(self, input_path: str, store_csv: bool = False, force_cached_or_offline: bool = False, skip_enrichment:bool = False) -> dict:
        if self.use_enrichment is False:
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
                apt_groups = []
                for relationship in enterprise_relationships:
                    if (relationship['target_object'] == technique['id']) and relationship['source_object'].startswith('intrusion-set'):
                        for group in enterprise_groups:
                            if relationship['source_object'] == group['id']:
                                apt_groups.append(group['group'])

                tactics = []
                if ('tactic' in technique):
                    for tactic in technique['tactic']:
                        tactics.append(tactic.replace('-',' ').title())

                self.addMitreID(technique, tactics, apt_groups)
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
                self.addMitreID(technique=technique_input, tactics=tactics_input, groups=groups_input)
            
                

        print("Done!")
        return attack_lookup