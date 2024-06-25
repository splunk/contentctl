from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)
import pathlib
import yaml

OUTPUT_FOLDER = "test_results"
OUTPUT_FILENAME = "summary.yml"


class DetectionTestingViewFile(DetectionTestingView):
    output_folder: str = OUTPUT_FOLDER
    output_filename: str = OUTPUT_FILENAME

    def getOutputFilePath(self) -> pathlib.Path:
        
        folder_path = pathlib.Path('.') / self.output_folder
        output_file = folder_path / self.output_filename

        return output_file

    def setup(self):
        pass

    def stop(self):
        folder_path = pathlib.Path('.') / self.output_folder
        output_file = self.getOutputFilePath()

        folder_path.mkdir(parents=True, exist_ok=True)
        
        
        result_dict = self.getSummaryObject()
        
        # use the yaml writer class
        with open(output_file, "w") as res:
            res.write(yaml.safe_dump(result_dict,sort_keys=False))

    def showStatus(self, interval: int = 60):
        pass

    def showResults(self):
        pass

    def createReport(self):
        pass
