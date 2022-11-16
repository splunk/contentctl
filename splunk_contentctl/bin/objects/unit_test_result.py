

from pydantic import BaseModel


from typing import Union
from datetime import timedelta

FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

class UnitTestResult(BaseModel):
    job_content:Union[dict,None]
    missing_observables:Union[None, list[str]]
    message:Union[None,str] 
    logic: bool = False
    noise: bool = False
    exception:bool = False
    success:bool = False

    def __init__(self, job_content:Union[dict,None], missing_observables:list[str]=[],  message:str="" ):
        self.job_content = job_content
        self.message = message
        self.missing_observables = missing_observables
        self.logic = False
        self.noise = False
        self.exception = False
        self.success = self.determine_success()

    def update_missing_observables(self, missing_observables:set[str]):
        self.missing_observables = list(missing_observables)
        self.success = self.determine_success()

    def determine_success(self):
        if self.job_content is None:
            self.exception = True
            return False
        
        if 'resultCount' in self.job_content and self.job_content['resultCount'] == 1:
            #in the future we probably want other metrics, about noise or others, here
            return True
        elif 'resultCount' in self.job_content and self.job_content['resultCount'] != 1:
            return False

        else:
            raise(Exception("Result created with indeterminate success."))
    
    def get_success(self)->bool:
        return self.success
    
    def get_time(self)->timedelta:
        if self.job_content is None:
            return timedelta(0)
        elif 'runDuration' in self.job_content:
            return timedelta(float(self.job_content['runDuration']))
        else:
           raise(Exception("runDuration missing from job."))