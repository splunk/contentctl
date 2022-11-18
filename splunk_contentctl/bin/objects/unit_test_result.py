

from pydantic import BaseModel, root_validator


from typing import Union
from datetime import timedelta
from splunklib.data import Record
FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

class UnitTestResult(BaseModel):
    job_content:Union [Record,None] = None
    missing_observables:Union[list[str],None] = None
    message:Union[None,str] = None
    logic: bool = False
    noise: bool = False
    exception:bool = False
    success:bool = False

    @root_validator(pre=False)
    def update_success(cls, values):
        if values['job_content'] is None:
            values['exception'] = True
            values['success'] = False
            return values    
        
        elif 'resultCount' in values['job_content'] and int(values['job_content']['resultCount']) == 1:
            #in the future we probably want other metrics, about noise or others, here
            values['success'] = True
            
        elif 'resultCount' in values['job_content'] and int(values['job_content']['resultCount']) != 1:
            values['success'] = False
            
        else:
            raise(Exception("Result created with indeterminate success."))
        return values
        
    def update_missing_observables(self, missing_observables:set[str]):
        self.missing_observables = list(missing_observables)
        self.success = self.determine_success()
    
    def determine_success(self)->bool:
        values_dict = self.update_success(self.__dict__)
        self.exception = values_dict['exception']
        self.success = values_dict['success']
        return self.success
    

    def get_job_field(self, fieldName:str):
        if self.job_content is None:
            return f"FIELD NAME {fieldName} does not exist in Job Content because Job Content is NONE"
        return self.job_content.get(fieldName, f"FIELD NAME {fieldName} does not exist in Job Content")
            
    def get_time(self)->timedelta:
        if self.job_content is None:
            return timedelta(0)
        elif 'runDuration' in self.job_content:
            duration = str(self.job_content['runDuration'])
            return timedelta(float(duration))
        else:
           raise(Exception("runDuration missing from job."))