import os
import sys
from typing import Union
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
     # Atomic Tests are first because parsing them 
     # is far quicker than attack_enrichment
     atomic_tests: Union[list[AtomicTest],None]
     attack_enrichment: AttackEnrichment
     detections: list[Detection]
     stories: list[Story]
     baselines: list[Baseline]
     investigations: list[Investigation]
     playbooks: list[Playbook]
     macros: list[Macro]
     lookups: list[Lookup]
     deployments: list[Deployment]
     ssa_detections: list[SSADetection]
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
        self.ssa_detection_builder = SSADetectionBuilder()
    
    def addContentToDictMappings(self, content:SecurityContentObject):
         content_name = content.name
         if isinstance(content,SSADetection):
            # Since SSA detections may have the same name as ESCU detection,
            # for this function we prepend 'SSA ' to the name.
            content_name = f"SSA {content_name}"               
         if content_name in self.output_dto.name_to_content_map:
            raise ValueError(f"Duplicate name '{content_name}' with paths:\n"
                             f" - {content.file_path}\n"
                             f" - {self.output_dto.name_to_content_map[content_name].file_path}")
         elif content.id in self.output_dto.uuid_to_content_map:
            raise ValueError(f"Duplicate id '{content.id}' with paths:\n"
                    f" - {content.file_path}\n"
                    f" - {self.output_dto.name_to_content_map[content_name].file_path}")
         
         self.output_dto.name_to_content_map[content_name] = content 
         self.output_dto.uuid_to_content_map[content.id] = content 
    
        
    
    def execute(self, input_dto: validate) -> None:
        self.input_dto = input_dto

        if self.input_dto.build_app or self.input_dto.build_api:
            self.createSecurityContent(SecurityContentType.deployments)
            self.createSecurityContent(SecurityContentType.lookups)
            self.createSecurityContent(SecurityContentType.macros)
            self.createSecurityContent(SecurityContentType.stories)
            self.createSecurityContent(SecurityContentType.baselines)
            self.createSecurityContent(SecurityContentType.investigations)
            self.createSecurityContent(SecurityContentType.playbooks)
            self.createSecurityContent(SecurityContentType.detections)
        
        if self.input_dto.build_ssa:
            self.createSecurityContent(SecurityContentType.ssa_detections)
        

    def createSecurityContent(self, contentType: SecurityContentType) -> None:
        if contentType == SecurityContentType.ssa_detections:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.path, 'ssa_detections'))
            security_content_files = [f for f in files if f.name.startswith('ssa___')]
            
        elif contentType in [SecurityContentType.deployments, 
                             SecurityContentType.lookups, 
                             SecurityContentType.macros, 
                             SecurityContentType.stories,
                             SecurityContentType.baselines,
                             SecurityContentType.investigations,
                             SecurityContentType.playbooks,
                             SecurityContentType.detections]:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.path, str(contentType.name)))
            security_content_files = [f for f in files if not f.name.startswith('ssa___')]
        else:
             raise(Exception(f"Cannot createSecurityContent for unknown product.  We must have at least one of 'build_app: True', 'build:api: True', and/or 'build_ssa: True' "))

        validation_errors = []
                
        already_ran = False
        progress_percent = 0
        
        for index,file in enumerate(security_content_files):
            progress_percent = ((index+1)/len(security_content_files)) * 100
            try:
                type_string = contentType.name.upper()
                modelDict = YmlReader.load_file(file)

                if contentType == SecurityContentType.lookups:
                        lookup = Lookup.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.lookups.append(lookup)
                        self.addContentToDictMappings(lookup)
                
                elif contentType == SecurityContentType.macros:
                        macro = Macro.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.macros.append(macro)
                        self.addContentToDictMappings(macro)
                
                elif contentType == SecurityContentType.deployments:
                        deployment = Deployment.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.deployments.append(deployment)
                        self.addContentToDictMappings(deployment)
                
                elif contentType == SecurityContentType.playbooks:
                        playbook = Playbook.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.playbooks.append(playbook)  
                        self.addContentToDictMappings(playbook)                  
                
                elif contentType == SecurityContentType.baselines:
                        baseline = Baseline.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.baselines.append(baseline)
                        self.addContentToDictMappings(baseline)
                
                elif contentType == SecurityContentType.investigations:
                        investigation = Investigation.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.investigations.append(investigation)
                        self.addContentToDictMappings(investigation)

                elif contentType == SecurityContentType.stories:
                        story = Story.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.stories.append(story)
                        self.addContentToDictMappings(story)
            
                elif contentType == SecurityContentType.detections:
                        detection = Detection.model_validate(modelDict,context={"output_dto":self.output_dto})
                        self.output_dto.detections.append(detection)
                        self.addContentToDictMappings(detection)

                elif contentType == SecurityContentType.ssa_detections:
                        self.constructSSADetection(self.ssa_detection_builder, self.output_dto,str(file))
                        ssa_detection = self.ssa_detection_builder.getObject()
                        if ssa_detection.status in [DetectionStatus.production.value, DetectionStatus.validation.value]:
                            self.output_dto.ssa_detections.append(ssa_detection)
                            self.addContentToDictMappings(ssa_detection)

                else:
                        raise Exception(f"Unsupported type: [{contentType}]")
                
                if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()) or not already_ran:
                        already_ran = True
                        print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
            
            except (ValidationError, ValueError) as e:
                relative_path = file.absolute().relative_to(self.input_dto.path.absolute())
                validation_errors.append((relative_path,e))
                

        print(f"\r{f'{contentType.name.upper()} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
        print("Done!")

        if len(validation_errors) > 0:
            errors_string = '\n\n'.join([f"File: {e_tuple[0]}\nError: {str(e_tuple[1])}" for e_tuple in validation_errors])
            #print(f"The following {len(validation_errors)} error(s) were found during validation:\n\n{errors_string}\n\nVALIDATION FAILED")
            # We quit after validation a single type/group of content because it can cause significant cascading errors in subsequent
            # types of content (since they may import or otherwise use it)
            raise Exception(f"The following {len(validation_errors)} error(s) were found during validation:\n\n{errors_string}\n\nVALIDATION FAILED")


    
    

    def constructSSADetection(self, builder: SSADetectionBuilder, directorOutput:DirectorOutputDto, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path,self.output_dto)
        builder.addMitreAttackEnrichmentNew(directorOutput.attack_enrichment)
        builder.addKillChainPhase()
        builder.addCIS()
        builder.addNist()
        builder.addAnnotations()
        builder.addMappings()
        builder.addUnitTest()
        builder.addRBA()


    