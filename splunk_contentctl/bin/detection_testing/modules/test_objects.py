from typing import Union
import pathlib
import yaml
import os
import json
import timeit
from datetime import timedelta

from bin.objects.detection import Detection
from bin.objects.unit_test_result import UnitTestResult





class DetectionResult:
    def __init__(self, detection:Detection):
        self.detection = detection
        
    
    def add_test_result(self, result:UnitTestResult):
        self.test_results.append(result)
    
    def get_total_time(self)->timedelta:
        runtimes = [result.get_time() for result in self.test_results]
        total_time = timedelta(0)
        for res in self.test_results:
            total_time += res.get_time()
        return total_time
    
    def get_success(self)->bool:
        if len(self.test_results) == 0:
            #If there have been no successful tests, then we cannot say anything was successful
            return False
        for res in self.test_results:
            if res.get_success is False:
                #If a single test Failed, then return failure
                return False
            
        #If we get here, then that means there was at least 1 test and
        #none of them failed, so success!
        return True

    def get_num_results(self)->int:
        return len(self.test_results)

class ResultsManager:
    def __init__(self):
        self.detectionResults:list[DetectionResult] = []

        # These are important for a running tally. Final summarization and 
        # output will independently calcualte these, though
        self.result_count = 0
        self.pass_count = 0
        self.fail_count = 0


    def addCompletedDetection(self, detectionResult:DetectionResult):
        #Record the overall result of the detection
        
        self.result_count += 1
        self.detectionResults.append(detectionResult)

        if not detectionResult.get_success():
            self.fail_count += 1 
            print(f"FAILURE: [{detectionResult.detection.name}]")
        else:
            self.pass_count += 1
            print(f"SUCCESS: [{detectionResult.detection.name}]")

        
        
        
        
        #We keep the whole thing because it removes the need to duplicate
        #certain fields when generating the summary
        self.detectionResults.append(detectionResult)
    


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
        background['detections'] = len(self.detectionResults)
        background['detections_pass'] = len([d for d in self.detectionResults if d.get_success()])
        background['detections_fail'] = len([d for d in self.detectionResults if not d.get_success()])
    

        background['tests'] = sum([len(d.detection.test.tests) for d in self.detectionResults])
        all_tests:list[Test] = []
        for detection in self.detections:
            for test in detection.testFile.tests:
                all_tests.append(test)
        background['tests_pass'] = len([t for t in all_tests if t.result is not None and t.result.success == True])
        background['tests_fail'] = len([t for t in all_tests if t.result is not None and t.result.success == False])
        background['total_time'] = str(timedelta(seconds = round(self.endTime - self.startTime)))

        


        return background

    def generate_detections_section(self)->list[dict]:
        results = []
        for detection in self.detections:
            success = True
            thisDetection = {"name"  : detection.detectionFile.name,
                             "id"    : detection.detectionFile.id,
                             "search": detection.detectionFile.search,
                             "path"  : str(detection.detectionFile.path),
                             "tests" : []}
            for test in detection.testFile.tests:
                if test.result is None:
                    raise(Exception(f"Detection {detection.detectionFile.name}, Test {test.name} in file {detection.testFile.path} was None, but should not be!"))
                testResult = {
                    "name": test.name,
                    "attack_data": [d.data for d in test.attack_data],
                    "success": test.result.success,
                    "logic": test.result.logic,
                    "noise": test.result.noise,
                    #"performance": test.result.performance,
                    "resultCount": test.result.resultCount,
                    "runDuration": test.result.runDuration,
                    "missing_observables": test.result.missing_observables
                }
                thisDetection['tests'].append(testResult)
                success = success and test.result.success
            thisDetection['success'] = success
            results.append(thisDetection)

        return results
    
    def generate_background_section(self)->dict:
        return {}

