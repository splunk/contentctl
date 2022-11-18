

from pydantic import BaseModel, root_validator


from typing import Union
from datetime import timedelta
from splunklib.data import Record
FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

class UnitTestResult(BaseModel):
    job_content:Union [Record,None] = None
    missing_observables:list[str] = []
    message:Union[None,str] = None
    logic: bool = False
    noise: bool = False
    exception:bool = False
    success:bool = False

    def get_summary(self, test_name:str, verbose=False)->str:
        lines:list[str] = []
        lines.append(f"SEARCH NAME        : '{test_name}'")
        if verbose or self.determine_success() == False:
            lines.append(f"SEARCH             : {self.get_search()}")
            lines.append(f"SUCCESS            : {self.determine_success()}")
            if self.exception is True:
                lines.append(f"EXCEPTION          : {self.exception}")
            if self.message is not None:
                lines.append(f"MESSAGE            : {self.message}")
        else:
            lines.append(f"SUCCESS            : {self.determine_success()}")
        if len(self.missing_observables) > 0:
            lines.append(f"MISSING OBSERVABLES: {self.missing_observables}")
                

        return "\n\t".join(lines)

    def get_search(self)->str:
        if self.job_content is not None:
            return self.job_content.get("search", "NO SEARCH FOUND - JOB MISSING SEARCH FIELD")
        return "NO SEARCH FOUND - JOB IS EMPTY"

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