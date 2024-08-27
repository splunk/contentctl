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
    def filter_tests(self, input_dto: TestInputDto) -> None:
        """
        If integration testing has NOT been enabled, then skip
        all of the integration tests. Otherwise, do nothing

        Args:
            input_dto (TestInputDto): A configuration of the test and all of the
            tests to be run.
        """        

        if not input_dto.config.enable_integration_testing:
            # Skip all integraiton tests if integration testing is not enabled:
            for detection in input_dto.detections:
                for test in detection.tests:
                    if isinstance(test, IntegrationTest):
                        test.skip("TEST SKIPPED: Skipping all integration tests")

        
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

        mode = input_dto.config.getModeName()
        if len(input_dto.detections) == 0:
            print(
                f"With Detection Testing Mode '{mode}', there were [0] detections found to test."
                "\nAs such, we will quit immediately."
            )
            # Directly call stop so that the summary.yml will be generated. Of course it will not
            # have any test results, but we still want it to contain a summary showing that now
            # detections were tested.
            file.stop()
        else:
            print(f"MODE: [{mode}] - Test [{len(input_dto.detections)}] detections")
            if mode in [DetectionTestingMode.changes.value, DetectionTestingMode.selected.value]:
                files_string = '\n- '.join(
                    [str(pathlib.Path(detection.file_path).relative_to(input_dto.config.path)) for detection in input_dto.detections]
                )
                print(f"Detections:\n- {files_string}")

            manager.setup()
            manager.execute()

        try:
            summary_results = file.getSummaryObject()
            summary = summary_results.get("summary", {})

            print(f"Test Summary (mode: {summary.get('mode','Error')})")
            print(f"\tSuccess                      : {summary.get('success',False)}")
            print(
                f"\tSuccess Rate                 : {summary.get('success_rate','ERROR')}"
            )
            print(
                f"\tTotal Detections             : {summary.get('total_detections','ERROR')}"
            )
            print(
                f"\tTotal Tested Detections      : {summary.get('total_tested_detections','ERROR')}"
            )
            print(
                f"\t  Passed Detections          : {summary.get('total_pass','ERROR')}"
            )
            print(
                f"\t  Failed Detections          : {summary.get('total_fail','ERROR')}"
            )
            print(
                f"\tSkipped Detections           : {summary.get('total_skipped','ERROR')}"
            )
            print(
                "\tProduction Status            :"
            )
            print(
                f"\t  Production Detections      : {summary.get('total_production','ERROR')}"
            )
            print(
                f"\t  Experimental Detections    : {summary.get('total_experimental','ERROR')}"
            )
            print(
                f"\t  Deprecated Detections      : {summary.get('total_deprecated','ERROR')}"
            )
            print(
                f"\tManually Tested Detections : {summary.get('total_manual','ERROR')}"
            )
            print(
                f"\tUntested Detections          : {summary.get('total_untested','ERROR')}"
            )
            print(f"\tTest Results File            : {file.getOutputFilePath()}")
            print(
                "\nNOTE: skipped detections include non-production, manually tested, and certain\n"
                "detection types (e.g. Correlation), but there may be overlap between these\n"
                "categories."
            )
            return summary_results.get("summary", {}).get("success", False)

        except Exception as e:
            print(f"Error determining if whole test was successful: {str(e)}")
            return False
