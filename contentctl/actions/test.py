from dataclasses import dataclass
from typing import List

from contentctl.objects.config import test_common
from contentctl.objects.enums import DetectionTestingMode, DetectionStatus, AnalyticsType
from contentctl.objects.detection import Detection

from contentctl.input.director import DirectorOutputDto

from contentctl.actions.detection_testing.DetectionTestingManager import (
    DetectionTestingManager,
    DetectionTestingManagerInputDto,
)


from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)


from contentctl.actions.detection_testing.views.DetectionTestingViewWeb import (
    DetectionTestingViewWeb,
)

from contentctl.actions.detection_testing.views.DetectionTestingViewCLI import (
    DetectionTestingViewCLI,
)

from contentctl.actions.detection_testing.views.DetectionTestingViewFile import (
    DetectionTestingViewFile,
)

from contentctl.objects.integration_test import IntegrationTest

import pathlib

MAXIMUM_CONFIGURATION_TIME_SECONDS = 600


@dataclass(frozen=True)
class TestInputDto:
    detections: List[Detection]
    config: test_common
    

class Test:

    def filter_detections(self, input_dto: TestInputDto)->TestInputDto:
        
        if not input_dto.config.enable_integration_testing:
            #Skip all integraiton tests if integration testing is not enabled:
            for detection in input_dto.detections:
                for test in detection.tests:
                    if isinstance(test, IntegrationTest):
                        test.skip("TEST SKIPPED: Skipping all integration tests")
        
        list_after_filtering:List[Detection] = []
        #extra filtering which may be removed/modified in the future
        for detection in input_dto.detections:
            if (detection.status != DetectionStatus.production.value):
                #print(f"{detection.name} - Not testing because [STATUS: {detection.status}]")
                pass
            elif detection.type == AnalyticsType.Correlation:
                #print(f"{detection.name} - Not testing because [  TYPE: {detection.type}]")
                pass
            else:
                list_after_filtering.append(detection)
        
        return TestInputDto(list_after_filtering, input_dto.config)
        
        
    def execute(self, input_dto: TestInputDto) -> bool:

        

        output_dto = DetectionTestingManagerOutputDto()

        web = DetectionTestingViewWeb(config=input_dto.config, sync_obj=output_dto)
        cli = DetectionTestingViewCLI(config=input_dto.config, sync_obj=output_dto)
        file = DetectionTestingViewFile(config=input_dto.config, sync_obj=output_dto)

        manager_input_dto = DetectionTestingManagerInputDto(
            config=input_dto.config,
            detections=input_dto.detections,
            views=[web, cli, file],
        )
        manager = DetectionTestingManager(
            input_dto=manager_input_dto, output_dto=output_dto
        )
        
        if len(input_dto.detections) == 0:
            print(f"With Detection Testing Mode '{input_dto.config.getModeName()}', there were [0] detections found to test.\nAs such, we will quit immediately.")
            # Directly call stop so that the summary.yml will be generated. Of course it will not have any test results, but we still want it to contain
            # a summary showing that now detections were tested.
            file.stop()
        else:
            print(f"MODE: [{input_dto.config.getModeName()}] - Test [{len(input_dto.detections)}] detections")
            if input_dto.config.mode in [DetectionTestingMode.changes, DetectionTestingMode.selected]:
                files_string = '\n- '.join([str(pathlib.Path(detection.file_path).relative_to(input_dto.config.path)) for detection in input_dto.detections])
                print(f"Detections:\n- {files_string}")

            manager.setup()
            manager.execute()
        
        try:
            summary_results = file.getSummaryObject()
            summary = summary_results.get("summary", {})

            print("Test Summary")
            print(f"\tSuccess                      : {summary.get('success',False)}")
            print(
                f"\tSuccess Rate                 : {summary.get('success_rate','ERROR')}"
            )
            print(
                f"\tTotal Detections             : {summary.get('total_detections','ERROR')}"
            )
            print(
                f"\tPassed Detections            : {summary.get('total_pass','ERROR')}"
            )
            print(
                f"\tFailed Detections            : {summary.get('total_fail','ERROR')}"
            )
            print(
                f"\tUntested Detections          : {summary.get('total_untested','ERROR')}"
            )
            print(f"\tTest Results File            : {file.getOutputFilePath()}")
            return summary_results.get("summary", {}).get("success", False)

        except Exception as e:
            print(f"Error determining if whole test was successful: {str(e)}")
            return False
