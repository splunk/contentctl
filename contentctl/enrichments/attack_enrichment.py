
from __future__ import annotations
import pathlib
from attackcti import attack_client
import logging
from pydantic import BaseModel, Field, ConfigDict
from contentctl.objects.config import validate
from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)

from attackcti.models import Technique, Relationship, Group, GroupTechnique

class AttackEnrichment(BaseModel):
    data: dict[str, MitreAttackEnrichment] = Field(default_factory=dict)
    use_enrichment:bool = True
    
    @staticmethod
    def getAttackEnrichment(config:validate)->AttackEnrichment:
        enrichment = AttackEnrichment(use_enrichment=config.enrichments)
        _ = enrichment.get_attack_lookup(config.mitre_cti_repo_path)
        return enrichment
    
    def getEnrichmentByMitreID(self, mitre_id:MITRE_ATTACK_ID_TYPE)->MitreAttackEnrichment:
        if not self.use_enrichment:
            raise Exception(f"Error, trying to add Mitre Enrichment, but use_enrichment was set to False")
        
        enrichment = self.data.get(mitre_id, None)
        if enrichment is not None:
            return enrichment
        else:
            raise Exception(f"Error, Unable to find Mitre Enrichment for MitreID {mitre_id}")
        
    
    def get_attack_lookup(self, input_path: pathlib.Path) -> None:
        if not self.use_enrichment:
            return None
            
        print(f"Parsing MITRE Enrichment Data...", end="", flush=True)
        try:
            #First try to get the info from 
            
            lift = attack_client(local_paths={
                "enterprise":str(input_path/"enterprise-attack"),
                "mobile":str(input_path/"ics-attack"),
                "ics":str(input_path/"mobile-attack")
            })
          

            from stix2.v20.sdo import AttackPattern


            all_techniques = lift.get_techniques_used_by_all_groups(stix_format=True)
            techs:list[GroupTechnique] = []
            for gt in all_techniques:
                techs.append(GroupTechnique.model_validate(gt))
            

            #Get all enterprise techniques and construct into objects
            '''
            techniques:list[AttackPattern | dict[str,Any]] = lift.get_enterprise_techniques(stix_format=False)
            
            enterprise_techniques:list[MitreEnterpriseTechnique] = []
            
            for t in techniques:
                #Field aliases have been set for from attackcti.models.Technique that we must fix
                # t.update(
                #     {
                #         "name":t['technique']
                #     }
                # )
                Technique.model_validate(t)
                enterprise_techniques.append(MitreEnterpriseTechnique.model_validate(t))
            

            #Get all relationships and parse into objects
            relationships_dict = lift.get_enterprise_relationships(stix_format=False)
            enterprise_relationships:list[MitreEnterpriseRelationship] = []
            for t in relationships_dict:
                #Field aliases have been set for from attackcti.models.Relationship that we must fix
                t.update(
                    {
                        "relationship_type":t['relationship'],
                        "source_ref":t['source_object'],
                        "target_ref":t['target_object']
                    }
                )
                Relationship.model_validate(t)
                enterprise_relationships.append(MitreEnterpriseRelationship.model_validate(t))
            # We only care about intrusion-set relationships
            enterprise_relationships = list(filter(lambda r: r.source_object.startswith('intrusion-set'), enterprise_relationships))

            # Get all enterprise groups and parse into objects
            groups_dict = lift.get_enterprise_groups(stix_format=False)
            enterprise_groups: list[MitreAttackGroup] = []
            for t in groups_dict:
                #Field aliases have been set for from attackcti.models.Group that we must fix
                t.update(
                    {
                        "name":t['group']
                    }
                )
                Group.model_validate(t)
                enterprise_groups.append(MitreAttackGroup.model_validate(t))

            # Using the relationships, assign the appropriate groups to each technique
            for tech in enterprise_techniques:                
                tech.updateGroups(enterprise_relationships,enterprise_groups)
        '''
            
        except Exception as err:
            print("ERROR")
            raise Exception(f"Error getting MITRE Enrichment: {str(err)}")
        
        print("done!")
        
        self.data = MitreAttackEnrichment.constructFromEnrichment(techs)



class MitreAttackEnrichment(BaseModel):
    ConfigDict(use_enum_values=True)
    mitre_attack_id: MITRE_ATTACK_ID_TYPE = Field(...)
    mitre_attack_technique: str = Field(...)
    mitre_attack_tactics: list[str] = Field(...)
    mitre_attack_groups: list[str] = Field(...)
    #Exclude this field from serialization - it is very large and not useful in JSON objects
    mitre_attack_group_objects: list[GroupTechnique] = Field(..., exclude=True)
    def __hash__(self) -> int:
        return id(self)
    
    @classmethod
    def constructFromEnrichment(cls, techniques_used_by_groups: list[GroupTechnique])->dict[MITRE_ATTACK_ID_TYPE, MitreAttackEnrichment]:
        mapping: dict[MITRE_ATTACK_ID_TYPE, MitreAttackEnrichment] = {}
        technique_ids = set([technique.technique_id for technique in techniques_used_by_groups])

        for technique_id in sorted(technique_ids):    
            all_groups = [group_technique for group_technique in techniques_used_by_groups if group_technique.technique_id == technique_id]
            # convert groups to proper pydantic groups due to field aliases
            mapping[technique_id] = cls(
                        mitre_attack_id=technique_id,
                        mitre_attack_technique=all_groups[0].technique,
                        mitre_attack_tactics=all_groups[0].tactic,
                        mitre_attack_groups=[group.group for group in all_groups],
                        mitre_attack_group_objects=all_groups)

        return mapping

'''    
from pydantic import BaseModel

class GrandParent(BaseModel):
    pass

class Parent(GrandParent):
    name: str

class Child(Parent):
    age: int

#Child has type child, as expected
child = Child(name="Tom", age=7)
print(type(child))
# <class 'Child'>

#Parent actually has type Child!
p = Parent.model_validate(child)
print(type(p))
# <class 'Child'>

# Grandparent also has type Child!
g = GrandParent.model_validate(child)
print(type(g))
# <class 'Child'>

pp = Parent(**child.dict())
type(pp)
#<class 'Parent'>



class Kidgparent():
    pass
    height=10

class Kidparent(Kidgparent):
    def __init__(self, name:str):
        self.name = name
class Kid(Kidparent):
    def __init__(self, name:str, age:int):
        self.age=age
        super().__init__(name=name)

kid = Kid(name="name", age=10)
'''