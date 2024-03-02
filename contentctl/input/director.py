import os
import sys
import pathlib
from dataclasses import dataclass, field
from pydantic import ValidationError
from uuid import UUID

    
    
    
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
     name_to_content_map: dict[str, SecurityContentObject] = field(default_factory=dict)
     uuid_to_content_map: dict[UUID, SecurityContentObject] = field(default_factory=dict)




from contentctl.input.basic_builder import BasicBuilder
from contentctl.input.detection_builder import DetectionBuilder
from contentctl.input.ssa_detection_builder import SSADetectionBuilder
from contentctl.input.playbook_builder import PlaybookBuilder
from contentctl.input.baseline_builder import BaselineBuilder
from contentctl.input.investigation_builder import InvestigationBuilder
from contentctl.input.story_builder import StoryBuilder
from contentctl.objects.enums import SecurityContentType

from contentctl.objects.enums import DetectionStatus 
from contentctl.helper.utils import Utils
from contentctl.enrichments.attack_enrichment import AttackEnrichment





     


class Director():
    input_dto: validate
    output_dto: DirectorOutputDto
    basic_builder: BasicBuilder
    playbook_builder: PlaybookBuilder
    baseline_builder: BaselineBuilder
    investigation_builder: InvestigationBuilder
    story_builder: StoryBuilder
    detection_builder: DetectionBuilder
    ssa_detection_builder: SSADetectionBuilder
    attack_enrichment: dict
    


    def __init__(self, output_dto: DirectorOutputDto) -> None:
        self.output_dto = output_dto
        self.attack_enrichment = dict()
    
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
        
        if self.input_dto.enrichments:
            self.attack_enrichment = AttackEnrichment.get_attack_lookup(str(self.input_dto.path))
        
        self.basic_builder = BasicBuilder()
        self.playbook_builder = PlaybookBuilder(self.input_dto.path)
        self.baseline_builder = BaselineBuilder()
        self.investigation_builder = InvestigationBuilder()
        self.story_builder = StoryBuilder()
        self.detection_builder = DetectionBuilder()
        self.ssa_detection_builder = SSADetectionBuilder()

        # Fetch and load all the atomic tests
        self.getAtomicTests()

        if self.input_dto.build_app or self.input_dto.build_app:
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

        if self.input_dto.build_app or self.input_dto.build_app:
            security_content_files = [f for f in files if not f.name.startswith('ssa___')]
        elif self.input_dto.build_ssa:
            security_content_files = [f for f in files if f.name.startswith('ssa___')]
        else:
            raise(Exception(f"Cannot createSecurityContent for unknown product."))

        
        for index,file in enumerate(security_content_files):
            progress_percent = ((index+1)/len(security_content_files)) * 100
            try:
                type_string = type.name.upper()
                if type == SecurityContentType.lookups:
                        self.constructLookup(self.basic_builder, file)
                        lookup = self.basic_builder.getObject()
                        self.output_dto.lookups.append(lookup)
                        self.addContentToDictMappings(lookup)
                
                elif type == SecurityContentType.macros:
                        self.constructMacro(self.basic_builder, file)
                        macro = self.basic_builder.getObject()
                        self.output_dto.macros.append(macro)
                        self.addContentToDictMappings(macro)
                
                elif type == SecurityContentType.deployments:
                        self.constructDeployment(self.basic_builder, file)
                        deployment = self.basic_builder.getObject()
                        self.output_dto.deployments.append(deployment)
                        self.addContentToDictMappings(deployment)
                
                elif type == SecurityContentType.playbooks:
                        self.constructPlaybook(self.playbook_builder, file)
                        playbook = self.playbook_builder.getObject()
                        self.output_dto.playbooks.append(playbook)  
                        self.addContentToDictMappings(playbook)                  
                
                elif type == SecurityContentType.baselines:
                        self.constructBaseline(self.baseline_builder, file)
                        baseline = self.baseline_builder.getObject()
                        self.output_dto.baselines.append(baseline)
                        self.addContentToDictMappings(baseline)
                
                elif type == SecurityContentType.investigations:
                        self.constructInvestigation(self.investigation_builder, file)
                        investigation = self.investigation_builder.getObject()
                        self.output_dto.investigations.append(investigation)
                        self.addContentToDictMappings(investigation)

                elif type == SecurityContentType.stories:
                        self.constructStory(self.story_builder, file)
                        story = self.story_builder.getObject()
                        self.output_dto.stories.append(story)
                        self.addContentToDictMappings(story)
            
                elif type == SecurityContentType.detections:
                        self.constructDetection(self.detection_builder, file)
                        detection = self.detection_builder.getObject()
                        self.output_dto.detections.append(detection)
                        self.addContentToDictMappings(detection)

                elif type == SecurityContentType.ssa_detections:
                        self.constructSSADetection(self.ssa_detection_builder, file)
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


    def constructDetection(self, builder: DetectionBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, self.output_dto)
        #builder.addDeployment(self.output_dto.deployments)
        builder.addMitreAttackEnrichment(self.attack_enrichment)
        #builder.addKillChainPhase()
        #builder.addCIS()
        #builder.addNist()
        #builder.addDatamodel()
        builder.addRBA()
        builder.addProvidingTechnologies()
        builder.addNesFields()
        builder.addAnnotations()
        builder.addMappings()
        #builder.addBaseline(self.output_dto.baselines)
        #builder.addPlaybook(self.output_dto.playbooks)
        #builder.addMacros(self.output_dto.macros)
        #builder.addLookups(self.output_dto.lookups)
        
        if self.input_dto.enrichments:
            builder.addMitreAttackEnrichment(self.attack_enrichment)
            builder.addCve()
    
        


    def constructSSADetection(self, builder: DetectionBuilder, file_path: str) -> None:
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


    def constructStory(self, builder: StoryBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path,self.output_dto)
        #builder.addDetections(self.output_dto.detections, self.input_dto.config)
        
        #builder.addInvestigations(self.output_dto.investigations)
        #builder.addBaselines(self.output_dto.baselines)
        builder.addAuthorCompanyName()


    def constructBaseline(self, builder: BaselineBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path,self.output_dto)
        #builder.addDeployment(self.output_dto.deployments)


    def constructDeployment(self, builder: BasicBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, SecurityContentType.deployments,self.output_dto)


    def constructLookup(self, builder: BasicBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, SecurityContentType.lookups,self.output_dto)


    def constructMacro(self, builder: BasicBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, SecurityContentType.macros,self.output_dto)


    def constructPlaybook(self, builder: PlaybookBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, self.output_dto)
        builder.addDetections()


    def constructTest(self, builder: BasicBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, SecurityContentType.unit_tests, self.output_dto)


    def constructInvestigation(self, builder: InvestigationBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path,self.output_dto)
        builder.addInputs()

    def constructObjects(self, builder: BasicBuilder, file_path: str) -> None:
        builder.reset()
        builder.setObject(file_path, self.output_dto)