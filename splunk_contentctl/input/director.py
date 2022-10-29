import os
import sys

from dataclasses import dataclass
from pydantic import ValidationError

from splunk_contentctl.input.basic_builder import BasicBuilder
from splunk_contentctl.input.detection_builder import DetectionBuilder
from splunk_contentctl.input.playbook_builder import PlaybookBuilder
from splunk_contentctl.input.baseline_builder import BaselineBuilder
from splunk_contentctl.input.investigation_builder import InvestigationBuilder
from splunk_contentctl.input.story_builder import StoryBuilder
from splunk_contentctl.objects.enums import SecurityContentType
from splunk_contentctl.objects.enums import SecurityContentProduct
from splunk_contentctl.helper.utils import Utils
from splunk_contentctl.enrichments.attack_enrichment import AttackEnrichment


@dataclass(frozen=True)
class DirectorInputDto:
    input_path: str
    product: SecurityContentProduct
    create_attack_csv : bool
    skip_enrichment: bool

@dataclass()
class DirectorOutputDto:
     detections: list
     stories: list
     baselines: list
     investigations: list
     playbooks: list
     deployments: list
     macros: list
     lookups: list
     tests: list

class Director():
    input_dto: DirectorInputDto
    output_dto: DirectorOutputDto
    basic_builder: BasicBuilder
    playbook_builder: PlaybookBuilder
    baseline_builder: BaselineBuilder
    investigation_builder: InvestigationBuilder
    story_builder: StoryBuilder
    detection_builder: DetectionBuilder
    attack_enrichment: dict


    def __init__(self, output_dto: DirectorOutputDto) -> None:
        self.output_dto = output_dto
        self.attack_enrichment = dict()


    def execute(self, input_dto: DirectorInputDto) -> None:
        self.input_dto = input_dto

        if not self.input_dto.skip_enrichment:
            self.attack_enrichment = AttackEnrichment.get_attack_lookup(self.input_dto.input_path, self.input_dto.create_attack_csv)

        self.basic_builder = BasicBuilder()
        self.playbook_builder = PlaybookBuilder(self.input_dto.input_path)
        self.baseline_builder = BaselineBuilder()
        self.investigation_builder = InvestigationBuilder()
        self.story_builder = StoryBuilder('ESCU')
        self.detection_builder = DetectionBuilder(self.input_dto.skip_enrichment)

        if self.input_dto.product == SecurityContentProduct.SPLUNK_ENTERPRISE_APP or self.input_dto.product == SecurityContentProduct.API:
            self.createSecurityContent(SecurityContentType.unit_tests)
            self.createSecurityContent(SecurityContentType.lookups)
            self.createSecurityContent(SecurityContentType.macros)
            self.createSecurityContent(SecurityContentType.deployments)
            self.createSecurityContent(SecurityContentType.baselines)
            self.createSecurityContent(SecurityContentType.investigations)
            self.createSecurityContent(SecurityContentType.playbooks)
            self.createSecurityContent(SecurityContentType.detections)
            self.createSecurityContent(SecurityContentType.stories)
        
        elif self.input_dto.product == SecurityContentProduct.SSA:
            self.createSecurityContent(SecurityContentType.unit_tests)
            self.createSecurityContent(SecurityContentType.detections)
            

    def createSecurityContent(self, type: SecurityContentType) -> list:
        objects = []
        if type == SecurityContentType.deployments:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name), 'ESCU'))
        elif type == SecurityContentType.unit_tests:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, 'tests'))
        else:
            files = Utils.get_all_yml_files_from_directory(os.path.join(self.input_dto.input_path, str(type.name)))

        validation_error_found = False
                
        already_ran = False
        progress_percent = 0
        type_string = "UNKNOWN TYPE"

        security_content_files = None

        if self.input_dto.product == SecurityContentProduct.SPLUNK_ENTERPRISE_APP or self.input_dto.product == SecurityContentProduct.API:
            security_content_files = [f for f in files if 'ssa___' not in f]
        elif self.input_dto.product == SecurityContentProduct.SSA:
            security_content_files = [f for f in files if 'ssa___' in f]


        for index,file in enumerate(security_content_files):
        
            print(file)
            #Index + 1 because we are zero indexed, not 1 indexed.  This ensures
            # that printouts end at 100%, not some other number 
            progress_percent = ((index+1)/len(security_content_files)) * 100
            try:
                type_string = "UNKNOWN TYPE"
                if type == SecurityContentType.lookups:
                        type_string = "Lookups"
                        self.constructLookup(self.basic_builder, file)
                        lookup = self.basic_builder.getObject()
                        self.output_dto.lookups.append(lookup)
                
                elif type == SecurityContentType.macros:
                        type_string = "Macros"
                        self.constructMacro(self.basic_builder, file)
                        macro = self.basic_builder.getObject()
                        self.output_dto.macros.append(macro)
                
                elif type == SecurityContentType.deployments:
                        type_string = "Deployments"
                        self.constructDeployment(self.basic_builder, file)
                        deployment = self.basic_builder.getObject()
                        self.output_dto.deployments.append(deployment)
                
                elif type == SecurityContentType.playbooks:
                        type_string = "Playbooks"
                        self.constructPlaybook(self.playbook_builder, file)
                        playbook = self.playbook_builder.getObject()
                        self.output_dto.playbooks.append(playbook)                    
                
                elif type == SecurityContentType.baselines:
                        type_string = "Baselines"
                        self.constructBaseline(self.baseline_builder, file, self.output_dto.deployments)
                        baseline = self.baseline_builder.getObject()
                        self.output_dto.baselines.append(baseline)
                
                elif type == SecurityContentType.investigations:
                        type_string = "Investigations"
                        self.constructInvestigation(self.investigation_builder, file)
                        investigation = self.investigation_builder.getObject()
                        self.output_dto.investigations.append(investigation)

                elif type == SecurityContentType.stories:
                        type_string = "Stories"
                        self.constructStory(self.story_builder, file, 
                            self.output_dto.detections, self.output_dto.baselines, self.output_dto.investigations)
                        story = self.story_builder.getObject()
                        self.output_dto.stories.append(story)
            
                elif type == SecurityContentType.detections:
                        type_string = "Detections"
                        self.constructDetection(self.detection_builder, file, 
                            self.output_dto.deployments, self.output_dto.playbooks, self.output_dto.baselines,
                            self.output_dto.tests, self.attack_enrichment, self.output_dto.macros,
                            self.output_dto.lookups, self.input_dto.skip_enrichment)
                        detection = self.detection_builder.getObject()
                        self.output_dto.detections.append(detection)
            
                elif type == SecurityContentType.unit_tests:
                        type_string = "Unit Tests"
                        self.constructTest(self.basic_builder, file)
                        test = self.basic_builder.getObject()
                        self.output_dto.tests.append(test)

                else:
                        raise Exception(f"Unsupported type: [{type}]")
                
                if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()) or not already_ran:
                        already_ran = True
                        print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
            
            except ValidationError as e:
                print('\nValidation Error for file ' + file)
                print(e)
                validation_error_found = True

        print(f"\r{f'{type_string} Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
        print("Done!")

        if validation_error_found:
            sys.exit(1)


    def constructDetection(self, builder: DetectionBuilder, path: str, deployments: list, playbooks: list, baselines: list, tests: list, attack_enrichment: dict, macros: list, lookups: list, skip_enrichment : bool) -> None:
        builder.reset()
        builder.setObject(path)
        builder.addDeployment(deployments)
        builder.addRBA()
        builder.addProvidingTechnologies()
        builder.addNesFields()
        builder.addAnnotations()
        builder.addMappings()
        builder.addBaseline(baselines)
        builder.addPlaybook(playbooks)
        builder.addUnitTest(tests)
        builder.addMacros(macros)
        builder.addLookups(lookups)
        
        if not skip_enrichment:
            builder.addMitreAttackEnrichment(self.attack_enrichment)
            builder.addCve()
            builder.addSplunkApp()


    def constructStory(self, builder: StoryBuilder, path: str, detections: list, baselines: list, investigations: list) -> None:
        builder.reset()
        builder.setObject(path)
        builder.addDetections(detections)
        builder.addInvestigations(investigations)
        builder.addBaselines(baselines)
        builder.addAuthorCompanyName()


    def constructBaseline(self, builder: BaselineBuilder, path: str, deployments: list) -> None:
        builder.reset()
        builder.setObject(path)
        builder.addDeployment(deployments)


    def constructDeployment(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path, SecurityContentType.deployments)


    def constructLookup(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path, SecurityContentType.lookups)


    def constructMacro(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path, SecurityContentType.macros)


    def constructPlaybook(self, builder: PlaybookBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path)
        builder.addDetections()


    def constructTest(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path, SecurityContentType.unit_tests)


    def constructInvestigation(self, builder: InvestigationBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path)
        builder.addInputs()
        builder.addLowercaseName()

    def constructObjects(self, builder: BasicBuilder, path: str) -> None:
        builder.reset()
        builder.setObject(path)