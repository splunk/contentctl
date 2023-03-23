from pydantic import BaseModel, root_validator, validator


from typing import Union
from datetime import timedelta
from splunklib.data import Record
from contentctl.objects.test_config import TestConfig
from contentctl.helper.utils import Utils

FORCE_TEST_FAILURE_FOR_MISSING_OBSERVABLE = False

SID_TEMPLATE = "{server}:{web_port}/en-US/app/search/search?sid={sid}"


class UnitTestResult(BaseModel):
    job_content: Union[Record, None] = None
    missing_observables: list[str] = []
    sid_link: Union[None, str] = None
    message: Union[None, str] = None
    exception: bool = False
    success: bool = False
    duration: float = 0

    class Config:
        validate_assignment = True

    def get_summary_dict(
        self,
        model_fields: list[str] = ["success", "exception", "message", "sid_link"],
        job_fields: list[str] = ["search", "resultCount", "runDuration"],
    ) -> dict:
        results_dict = {}
        for field in model_fields:
            value = getattr(self, field)
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
        content: Union[Record, None, Exception],
        config: TestConfig,
        success: bool = False,
        duration: float = 0,
    ):
        self.duration = round(duration, 2)
        if isinstance(content, Record):
            self.job_content = content
            self.success = success
            if success:
                self.message = "TEST PASSED"
            else:
                self.message = "TEST FAILED"
            self.exception = False

            if not config.test_instance_address.startswith("http://"):
                sid_template = f"http://{SID_TEMPLATE}"
            else:
                sid_template = SID_TEMPLATE
            self.sid_link = sid_template.format(
                server=config.test_instance_address,
                web_port=config.web_ui_port,
                sid=content.get("sid", None),
            )

        elif isinstance(content, Exception):
            self.job_content = None
            self.success = False
            self.exception = True
            self.message = f"Error during test: {str(content)}"

        elif content is None:
            self.job_content = None
            self.success = False
            self.exception = True
            self.message = f"Error during test: unable to run test"

        else:
            msg = f"Error: Unknown type for content in UnitTestResult: {type(content)}"
            print(msg)
            self.job_content = None
            self.success = False
            self.exception = True
            self.message = f"Error during test - unable to run test {msg}"
        return self.success

    """
    def get_summary(self, test_name: str, verbose=False) -> str:
        lines: list[str] = []
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

    def get_search(self) -> str:
        if self.job_content is not None:
            return self.job_content.get(
                "search", "NO SEARCH FOUND - JOB MISSING SEARCH FIELD"
            )
        return "NO SEARCH FOUND - JOB IS EMPTY"

    def add_message(self, message: str):
        if self.message is None:
            self.message = message
        else:
            self.message += f"\n{message}"

    @root_validator(pre=False)
    def update_success(cls, values):
        if values["job_content"] is None:
            values["exception"] = True
            values["success"] = False
            if values["message"] is None:
                # If the message has not been overridden, then put in a default
                values["message"] = "Job Content was None - unknown failure reason"
            # Otherwise, a message has been passed so don't overwrite it
            return values

        if "messages" in values["job_content"]:
            fatal_or_error = False
            all_messages = values["job_content"]["messages"]
            unique_messages = set()
            for level, level_messages in all_messages.items():
                if level in ["info"]:
                    # we will skip any info messages
                    continue
                elif level in ["fatal", "error"]:
                    for msg in level_messages:
                        # These error indicate a failure - the search was
                        # not successful. They are important for debugging,
                        # so we will pass them to the user.
                        # They also represent a an error during the test
                        values["logic"] = False
                        values["success"] = False
                        values["exception"] = True
                        unique_messages.add(msg)
                        fatal_or_error = True
                else:
                    unknown_messages_as_single_string = "\n".join(level_messages)
                    unique_messages.add(unknown_messages_as_single_string)

            if len(unique_messages) == 0:
                values["message"] = None  # No messages

            else:
                # Merge all those messages together
                values["message"] = "\n".join(unique_messages)

            if fatal_or_error:
                return values

        # Can there still be a success even if there was an error/fatal message above? Probably not?
        if (
            "resultCount" in values["job_content"]
            and int(values["job_content"]["resultCount"]) == 1
        ):
            # in the future we probably want other metrics, about noise or others, here
            values["logic"] = True
            values["success"] = True

        elif (
            "resultCount" in values["job_content"]
            and int(values["job_content"]["resultCount"]) != 1
        ):
            values["logic"] = False
            values["success"] = False

        else:
            raise (Exception("Result created with indeterminate success."))

        return values

    def update_missing_observables(self, missing_observables: set[str]):
        self.missing_observables = list(missing_observables)
        self.success = self.determine_success()

    def determine_success(self) -> bool:
        # values_dict = self.update_success(self.__dict__)
        # self.exception = values_dict['exception']
        # self.success = values_dict['success']
        return self.success

    def get_job_field(self, fieldName: str):
        if self.job_content is None:
            # return f"FIELD NAME {fieldName} does not exist in Job Content because Job Content is NONE"
            return None
        return self.job_content.get(fieldName, None)

    def get_time(self) -> timedelta:
        if self.job_content is None:
            return timedelta(0)
        elif "runDuration" in self.job_content:
            duration = str(self.job_content["runDuration"])
            return timedelta(float(duration))
        else:
            raise (Exception("runDuration missing from job."))
    """
