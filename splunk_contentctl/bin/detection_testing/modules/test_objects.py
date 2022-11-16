from typing import Union
import pathlib
import yaml
import os
import json
import timeit
from datetime import timedelta, datetime

from bin.objects.detection import Detection
from bin.objects.unit_test_result import UnitTestResult


class ResultsManager:
    def __init__(self):
        self.detections:list[Detection] = []

        # These are important for a running tally. Final summarization and 
        # output will independently calcualte these, though
        self.result_count = 0
        self.pass_count = 0
        self.fail_count = 0
        self.start_time = datetime.now()
        


    def addCompletedDetection(self, detection:Detection):
        #Record the overall result of the detection
        
        self.result_count += 1
        self.detections.append(detection)

        if not detection.get_success():
            self.fail_count += 1 
            print(f"FAILURE: [{detection.name}]")
        else:
            self.pass_count += 1
            print(f"SUCCESS: [{detection.name}]")

        
        
        
        
        #We keep the whole thing because it removes the need to duplicate
        #certain fields when generating the summary
        self.detections.append(detection)
    


    def generate_results_file(self, filePath:pathlib.Path, root_folder:pathlib.Path = pathlib.Path("test_results"))->bool:
        #Make the folder if it doesn't already exist.  If it does, that's ok
        root_folder.mkdir(parents=True, exist_ok=True)
        full_path = root_folder / filePath
        try:
            background = self.generate_background_section()
            summary = self.generate_summary_section()
            detections = self.generate_detections_section()
            obj = {"background": background, "summary": summary, "detections": detections}
            with open(full_path, "w") as output:
                json.dump(obj, output, indent=3)
            return True
        except Exception as e:
            print(f"Error generating result file: {str(e)}")
            return False
    
    def generate_summary_section(self)->dict:
        if self.endTime is None:
            self.endTime = timeit.default_timer()
        
        background = {}
        background['detections'] = len(self.detections)
        background['detections_pass'] = len([d for d in self.detections if d.get_success()])
        background['detections_fail'] = len([d for d in self.detections if not d.get_success()])
    

        background['tests'] = sum([d.get_num_tests() for d in self.detections])
        all_tests:list[Union[None,UnitTestResult]] = []
        for detection in self.detections:
            for test in detection.get_all_unit_test_results():
                all_tests.append(test)
        background['tests_pass'] = len([t for t in all_tests if t is not None and t.success == True])
        background['tests_fail'] = len([t for t in all_tests if t is None or t.success == False])

        duration = datetime.now() - self.start_time
        duration_without_microseconds = duration - timedelta(microseconds=duration.microseconds)
        background['total_time'] = str(duration_without_microseconds)

        return background

    def generate_detections_section(self)->list[dict]:
        results = []
        for detection in self.detections:
            success = True
            thisDetection = {"name"  : detection.name,
                             "id"    : detection.id,
                             "search": detection.search,
                             "path"  : str(detection.file_path),
                             "tests" : []}
            for test in detection.test.tests:
                #Set all the default fields which we can show, even if there 
                #is an error
                test_success = False
                test_result = {
                        "name": test.name,
                        "attack_data": [d.data for d in test.attack_data],
                        "success": False,
                        "logic": False,
                        "noise": False,
                        "resultCount": 0,
                        "runDuration": 0,
                        "missing_observables": []
                    }
                
                if test.result is None:
                    #This test was not run for some reason
                    message = "Test Result was None"
                    test_result['message'] = message
                elif test.result.job is None:
                    message = "Test Result Job was None"
                    test_result['message'] = message
                elif test.result.exception:
                    #There was an exception detection when running this test
                    message = "Encountered Exception while running the test."
                    test_result['message'] = message

                

                else:
                    #If something unexpected happens, should we raise an exception?
                    #if result.job is None:
                    #    raise(Exception(f"Detection {detection.name}, Test {test.name} in file {detection.file_path} was None, but should not be!"))
                    test_result["success"] = test.result.success,
                    test_result["logic"] = test.result.logic,
                    test_result["noise"] = test.result.noise,
                    test_result["resultCount"] = float(test.result.job['resultCount']),
                    test_result["runDuration"] = float(test.result.job['runDuration']),
                    test_result["missing_observables"] = test.result.missing_observables
                    test_success = test.result.success

                thisDetection['tests'].append(test_result)

                success = success and test_success
            
            thisDetection['success'] = success
            results.append(thisDetection)

        return results
    
    def generate_background_section(self)->dict:
        return {}

