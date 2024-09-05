
from __future__ import annotations
import csv
import pathlib
import os
import sys
from attackcti import attack_client
import json
import logging
from pydantic import BaseModel, Field
from dataclasses import field
from typing import Annotated,Any
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment, MitreEnterpriseTechnique, MitreEnterpriseRelationship, MitreAttackGroup
from contentctl.objects.config import validate
from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)


class AttackEnrichment(BaseModel):
    data: dict[str, MitreEnterpriseTechnique] = field(default_factory=dict)
    use_enrichment:bool = True
    
    @staticmethod
    def getAttackEnrichment(config:validate)->AttackEnrichment:
        enrichment = AttackEnrichment(use_enrichment=config.enrichments)
        _ = enrichment.get_attack_lookup(str(config.path))
        return enrichment
    
    def getEnrichmentByMitreID(self, mitre_id:MITRE_ATTACK_ID_TYPE)->MitreEnterpriseTechnique:
        if not self.use_enrichment:
            raise Exception(f"Error, trying to add Mitre Enrichment, but use_enrichment was set to False")
        
        enrichment = self.data.get(mitre_id, None)
        if enrichment is not None:
            return enrichment
        else:
            raise Exception(f"Error, Unable to find Mitre Enrichment for MitreID {mitre_id}")
        
    
    def get_attack_lookup(self, input_path: str, store_csv: bool = False) -> dict[str,MitreEnterpriseTechnique]:
        local_mitre_enrichment_path = pathlib.Path(input_path)/"mitre_enrichment.json"
        if not self.use_enrichment:
            return {}
        print("Getting MITRE Attack Enrichment Data. This may take some time...")
       
        try:
            print(f"\r{'Client'.rjust(23)}: [{0:3.0f}%]...", end="", flush=True)
            lift = attack_client()
            print(f"\r{'Client'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Techniques'.rjust(23)}: [{0.0:3.0f}%]...", end="", flush=True)
            all_enterprise_techniques = lift.get_enterprise_techniques(stix_format=False)
            
            et:list[MitreEnterpriseTechnique] = []
            for t in all_enterprise_techniques:
                try:
                    et.append(MitreEnterpriseTechnique.model_validate(t))
                except Exception as e:
                    print(e)

            print(f"\r{'Techniques'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Relationships'.rjust(23)}: [{0.0:3.0f}%]...", end="", flush=True)
            enterprise_relationships = lift.get_enterprise_relationships(stix_format=False)
            print(f"\r{'Relationships'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            
            er:list[MitreEnterpriseRelationship] = []
            for t in enterprise_relationships:
                er.append(MitreEnterpriseRelationship.model_validate(t))
            # We only care about intrusion-set relationships
            er = list(filter(lambda r: r.source_object.startswith('intrusion-set'), er))

            print(f"\r{'Groups'.rjust(23)}: [{0:3.0f}%]...", end="", flush=True)
            enterprise_groups = lift.get_enterprise_groups(stix_format=False)
            print(f"\r{'Groups'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            eg: list[MitreAttackGroup] = []
            for t in enterprise_groups:
                eg.append(MitreAttackGroup.model_validate(t))
            
            for tech in et:                
                tech.updateGroups(er,eg)
            
            print(f"Update {local_mitre_enrichment_path} with latest values")
            
            with open(local_mitre_enrichment_path, mode='w') as outp:
                dumped = [m.model_dump() for m in et]
                json.dump(dumped,outp, indent=3)
                



        except Exception as err:
            print(f'\nError: {str(err)}')
            print(f"Use local copy {local_mitre_enrichment_path}")
            if not local_mitre_enrichment_path.is_file():
                raise FileNotFoundError(f"The local MITRE Enrichment file {local_mitre_enrichment_path} does not exist")
            with open(local_mitre_enrichment_path, mode='r') as inp:
                mitre_enrichment_as_json:list[dict[str,Any]] = json.load(inp)
            
            et:list[MitreEnterpriseTechnique] = []
            for json_obj in mitre_enrichment_as_json:
                et.append(MitreEnterpriseTechnique.model_validate(json_obj))
            
            
                

        print("Done!")
        self.data = {tactic.technique_id: tactic for tactic in et}