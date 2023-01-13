from argparse import Namespace
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.detection_testing_execution import main
from splunk_contentctl.actions.generate import DirectorOutputDto
from threading import Thread, Barrier
from splunk_contentctl.objects.detection import Detection

MAXIMUM_CONFIGURATION_TIME_SECONDS = 600


class Test:
    def execute(self, config: TestConfig, detections: list[Detection]) -> None:
        # Instead of waiting for the content pack generation to complete
        # before setting up the instance(s), configure them while we are
        # generating the content pack.  Then, use a barrier to wait until
        # both are ready before deploying the app to the target instance(s)
        # setup_barrier = Barrier(2, timeout=MAXIMUM_CONFIGURATION_TIME_SECONDS)

        # infrastructure_preparation_thread = Thread(
        #     target=self.prepare_test_infrastructure, args=(config, setup_barrier)
        # )
        # infrastructure_preparation_thread.start()

        main(config, detections)

    def prepare_test_infrastructure(self, config: TestConfig, barrier: Barrier):
        print("Preparing infrastructure")
