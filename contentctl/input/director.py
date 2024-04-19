import os
import sys
import pathlib
from dataclasses import dataclass, field
from pydantic import ValidationError
from uuid import UUID
from contentctl.input.yml_reader import YmlReader
    
    
    
from contentctl.objects.detection import Detection
from contentctl.objects.story import Story

from contentctl.objects.enums import SecurityContentProduct
from contentctl.objects.baseline import Baseline
from contentctl.objects.investigation import Investigation
from contentctl.objects.playbook import Playbook
from contentctl.objects.deployment import Deployment
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.ssa_detection import SSADetection
from contentctl.objects.atomic import AtomicTest
from contentctl.objects.security_content_object import SecurityContentObject

from contentctl.enrichments.attack_enrichment import AttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment

from contentctl.objects.config import validate



@dataclass()
class DirectorOutputDto:
     detections: list[Detection]
     stories: list[Story]
     baselines: list[Baseline]
     investigations: list[Investigation]
     playbooks: list[Playbook]
     macros: list[Macro]
     lookups: list[Lookup]
     deployments: list[Deployment]
     ssa_detections: list[SSADetection]
     atomic_tests: list[AtomicTest]
     attack_enrichment: AttackEnrichment
     #cve_enrichment: CveEnrichment

     name_to_content_map: dict[str, SecurityContentObject] = field(default_factory=dict)
     uuid_to_content_map: dict[UUID, SecurityContentObject] = field(default_factory=dict)
     




from contentctl.input.ssa_detection_builder import SSADetectionBuilder
from contentctl.objects.enums import SecurityContentType

from contentctl.objects.enums import DetectionStatus 
from contentctl.helper.utils import Utils






     


class Director():
    input_dto: validate
    output_dto: DirectorOutputDto
    ssa_detection_builder: SSADetectionBuilder
    


    def __init__(self, output_dto: DirectorOutputDto) -> None:
        self.output_dto = output_dto
        
    
    def addContentToDictMappings(self, content:SecurityContentObject):
         if content.name in self.output_dto.name_to_content_map:
            raise ValueError(f"Duplicate name '{content.name}' with paths:\n"
                             f" - {content.file_path}\n"
                             f" - {self.output_dto.name_to_content_map[content.name].file_path}")
         elif content.id in self.output_dto.uuid_to_content_map:
            raise ValueError(f"Duplicate id '{content.id}' with paths:\n"
                    f" - {content.file_path}\n"
                    f" - {self.output_dto.name_to_content_map[content.name].file_path}")
         
         self.output_dto.name_to_content_map[content.name] = content 
         self.output_dto.uuid_to_content_map[content.id] = content 
    
    def getAtomicTests(self)->None:
         self.output_dto.atomic_tests = AtomicTest.getAtomicTestsFromArtRepo()
        
    
    def execute(self, input_dto: validate) -> None:
        self.input_dto = input_dto

        # Fetch and load all the atomic tests
        self.getAtomicTests()

        if self.input_dto.build_app or self.input_dto.build_api:
            self.createSecurityContent(SecurityContentType.deployments)
            self.createSecurityContent(SecurityContentType.lookups)
            self.createSecurityContent(SecurityContentType.macros)
            self.createSecurityContent(SecurityContentType.stories)
            self.createSecurityContent(SecurityContentType.baselines)
            self.createSecurityContent(SecurityContentType.investigations)
            self.createSecurityContent(SecurityContentType.playbooks)
            self.createSecurityContent(SecurityContentType.detections)
        
        elif self.input_dto.build_ssa == SecurityContentProduct.SSA:
            self.createSecurityContent(SecurityContentType.ssa_detections)
        

    def createSecurityContent(self, type: SecurityContentType) -> None:
        if type == SecurityContentType.ssa_detections:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.path, 'ssa_detections'))
        else:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.path, str(type.name)))

        validation_errors = []
                
        already_ran = False
        progress_percent = 0

        if self.input_dto.build_app or self.input_dto.build_api:
            security_content_files = [f for f in files if not f.name.startswith('ssa___')]
        elif self.input_dto.build_ssa:
            security_content_files = [f for f in files if f.name.startswith('ssa___')]
        else:
            raise(Exception(f"Cannot createSecurityContent for unknown product.  We must have at least one of 'build_app: True', 'build:api: True', and/or 'build_ssa: True' "))

        
        for index,file in enumerate(security_content_files):
            progress_percent = ((index+1)/len(security_content_files)) * 100
            try:
                type_string = type.name.upper()
                modelDict = YmlReader.load_file(file)

                if type == SecurityContentType.lookups:
                        lookup = Lookup.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.lookups.append(lookup)
                        self.addContentToDictMappings(lookup)
                
                elif type == SecurityContentType.macros:
                        macro = Macro.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.macros.append(macro)
                        self.addContentToDictMappings(macro)
                
                elif type == SecurityContentType.deployments:
                        deployment = Deployment.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.deployments.append(deployment)
                        self.addContentToDictMappings(deployment)
                
                elif type == SecurityContentType.playbooks:
                        playbook = Playbook.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.playbooks.append(playbook)  
                        self.addContentToDictMappings(playbook)                  
                
                elif type == SecurityContentType.baselines:
                        baseline = Baseline.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.baselines.append(baseline)
                        self.addContentToDictMappings(baseline)
                
                elif type == SecurityContentType.investigations:
                        investigation = Investigation.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.investigations.append(investigation)
                        self.addContentToDictMappings(investigation)

                elif type == SecurityContentType.stories:
                        story = Story.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.stories.append(story)
                        self.addContentToDictMappings(story)
            
                elif type == SecurityContentType.detections:
                        detection = Detection.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.detections.append(detection)
                        self.addContentToDictMappings(detection)

                elif type == SecurityContentType.ssa_detections:
                        self.constructSSADetection(self.ssa_detection_builder, str(file))
                        ssa_detection = self.ssa_detection_builder.getObject()
                        if ssa_detection.status in  [DetectionStatus.production.value, DetectionStatus.validation.value]:
                            self.output_dto.ssa_detections.append(ssa_detection)
                            self.addContentToDictMappings(ssa_detection)

                else:
                        raise Exception(f"Unsupported type: [{type}]")
                
                if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()) or not already_ran:
                        already_ran = True
                        print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
            
            except (ValidationError, ValueError) as e:
                relative_path = file.absolute().relative_to(self.input_dto.path.absolute())
                validation_errors.append((relative_path,e))
                

        print(f"\r{f'{type.name.upper()} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
        print("Done!")

        if len(validation_errors) > 0:
            errors_string = '\n\n'.join([f"File: {e_tuple[0]}\nError: {str(e_tuple[1])}" for e_tuple in validation_errors])
            #print(f"The following {len(validation_errors)} error(s) were found during validation:\n\n{errors_string}\n\nVALIDATION FAILED")
            # We quit after validation a single type/group of content because it can cause significant cascading errors in subsequent
            # types of content (since they may import or otherwise use it)
            raise Exception(f"The following {len(validation_errors)} error(s) were found during validation:\n\n{errors_string}\n\nVALIDATION FAILED")


    
    

    def constructSSADetection(self, builder: SSADetectionBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path,self.output_dto)
        builder.addMitreAttackEnrichment(self.attack_enrichment)
        builder.addKillChainPhase()
        builder.addCIS()
        builder.addNist()
        builder.addAnnotations()
        builder.addMappings()
        builder.addUnitTest()
        builder.addRBA()


    