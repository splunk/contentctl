from pydantic import BaseModel, root_validator, validator


from typing import Union
from datetime import timedelta
from splunklib.data import Record
from contentctl.objects.test_config import Infrastructure
from contentctl.helper.utils import Utils

FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

NO_SID = "Testing Failed, NO Search ID"
SID_TEMPLATE = "{server}:{web_port}/en-US/app/search/search?sid={sid}"


class UnitTestResult(BaseModel):
    job_content: Union[Record, None] = None
    missing_observables: list[str] = []
    sid_link: Union[None, str] = None
    message: Union[None, str] = None
    exception: Union[Exception,None] = None
    success: bool = False
    duration: float = 0

    class Config:
        validate_assignment = True
        arbitrary_types_allowed = True

    def get_summary_dict(
        self,
        model_fields: list[str] = ["success", "exception", "message", "sid_link"],
        job_fields: list[str] = ["search", "resultCount", "runDuration"],
    ) -> dict:
        results_dict = {}
        for field in model_fields:
            if getattr(self, field) is not None:
                if isinstance(getattr(self, field), Exception):
                    #Exception cannot be serialized, so convert to str
                    results_dict[field] = str(getattr(self, field))
                else:
                    results_dict[field] = getattr(self, field)

        for field in job_fields:
            if self.job_content is not None:
                value = self.job_content.get(field, None)
                if field == "runDuration":
                    try:
                        value = Utils.getFixedWidth(float(value), 3)
                    except Exception as e:
                        value = Utils.getFixedWidth(0, 3)
                results_dict[field] = value
            else:
                results_dict[field] = None

        return results_dict

    def set_job_content(
        self,
        content: Union[Record, None],
        config: Infrastructure,
        exception: Union[Exception, None] = None,
        success: bool = False,
        duration: float = 0,
    ):
        self.duration = round(duration, 2)
        self.exception = exception
        self.success = success

        if content is not None:
            self.job_content = content
            
            if success:
                self.message = "TEST PASSED"
            else:
                self.message = "TEST FAILED"
            

            if not config.instance_address.startswith("http://"):
                sid_template = f"http://{SID_TEMPLATE}"
            else:
                sid_template = SID_TEMPLATE
            self.sid_link = sid_template.format(
                server=config.instance_address,
                web_port=config.web_ui_port,
                sid=content.get("sid", None),
            )

        elif content is None:
            self.job_content = None
            self.success = False
            if self.exception is not None:
                self.message = f"EXCEPTION: {str(self.exception)}"
            self.sid_link = NO_SID

        return self.success

    