from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingInfrastructure,
)


class DetectionTestingInfrastructureServer(DetectionTestingInfrastructure):
    def start(self):
        pass

    def finish(self):
        super().finish()

    def get_name(self):
        return self.config.container_name
