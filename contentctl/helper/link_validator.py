import abc
import os
import shelve
import time
from typing import Any, Callable, Union

import requests
import urllib3
import urllib3.exceptions
from pydantic import BaseModel, model_validator

DEFAULT_USER_AGENT_STRING = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36"
ALLOWED_HTTP_CODES = [200]


class LinkStats(BaseModel):
    # Static Values
    method: Callable = requests.get
    allowed_http_codes: list[int] = ALLOWED_HTTP_CODES
    access_count: int = 1  # when constructor is called, it has been accessed once!
    timeout_seconds: int = 15
    allow_redirects: bool = True
    headers: dict = {"User-Agent": DEFAULT_USER_AGENT_STRING}
    verify_ssl: bool = False
    if verify_ssl is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Values generated at runtime.
    # We need to assign these some default values to get the
    # validation working since ComputedField has not yet been
    # introduced to Pydantic
    reference: str
    referencing_files: set[str]
    redirect: Union[str, None] = None
    status_code: int = 0
    valid: bool = False
    resolution_time: float = 0

    def is_link_valid(self, referencing_file: str) -> bool:
        self.access_count += 1
        self.referencing_files.add(referencing_file)
        return self.valid

    @model_validator(mode="before")
    def check_reference(cls, data: Any) -> Any:
        start_time = time.time()
        # Get out all the fields names to make them easier to reference
        method = data["method"]
        reference = data["reference"]
        timeout_seconds = data["timeout_seconds"]
        headers = data["headers"]
        allow_redirects = data["allow_redirects"]
        verify_ssl = data["verify_ssl"]
        allowed_http_codes = data["allowed_http_codes"]
        if not (reference.startswith("http://") or reference.startswith("https://")):
            raise (
                ValueError(
                    f"Reference {reference} does not begin with http(s). Only http(s) references are supported"
                )
            )

        try:
            get = method(
                reference,
                timeout=timeout_seconds,
                headers=headers,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
            )
            resolution_time = time.time() - start_time
            data["status_code"] = get.status_code
            data["resolution_time"] = resolution_time
            if reference != get.url:
                data["redirect"] = get.url
            else:
                data["redirect"] = None  # None is also already the default

            # Returns the updated values and sets them for the object
            if get.status_code in allowed_http_codes:
                data["valid"] = True
            else:
                # print(f"Unacceptable HTTP Status Code {get.status_code} received for {reference}")
                data["valid"] = False
            return data

        except Exception:
            resolution_time = time.time() - start_time
            # print(f"Reference {reference} was not reachable after {resolution_time:.2f} seconds")
            data["status_code"] = 0
            data["valid"] = False
            data["redirect"] = None
            data["resolution_time"] = resolution_time
            return data


class LinkValidator(abc.ABC):
    cache: Union[dict[str, LinkStats], shelve.Shelf] = {}
    uncached_checks: int = 0
    total_checks: int = 0
    # cache: dict[str,LinkStats] = {}

    use_file_cache: bool = False
    reference_cache_file: str = "lookups/REFERENCE_CACHE.db"

    @staticmethod
    def initialize_cache(use_file_cache: bool = False):
        LinkValidator.use_file_cache = use_file_cache
        if use_file_cache is False:
            return
        if not os.path.exists(LinkValidator.reference_cache_file):
            print(
                f"Cache at {LinkValidator.reference_cache_file} not found - Creating it."
            )

        try:
            LinkValidator.cache = shelve.open(
                LinkValidator.reference_cache_file, flag="c", writeback=True
            )
        except Exception:
            print(
                f"Failed to create the cache file {LinkValidator.reference_cache_file}.  Reference info will not be cached."
            )
            LinkValidator.cache = {}

        # Remove all of the failures to force those resources to be resolved again
        failed_refs = []
        for ref in LinkValidator.cache.keys():
            if LinkValidator.cache[ref].status_code not in ALLOWED_HTTP_CODES:
                failed_refs.append(ref)
                # can't remove it here because this will throw an error:
                # cannot change size of dictionary while iterating over it
            else:
                # Set the reference count to 0 and referencing files to empty set
                LinkValidator.cache[ref].access_count = 0
                LinkValidator.cache[ref].referencing_files = set()

        for ref in failed_refs:
            del LinkValidator.cache[ref]

    @staticmethod
    def close_cache():
        if LinkValidator.use_file_cache:
            LinkValidator.cache.close()

    @staticmethod
    def validate_reference(
        reference: str, referencing_file: str, raise_exception_if_failure: bool = False
    ) -> bool:
        LinkValidator.total_checks += 1
        if reference not in LinkValidator.cache:
            LinkValidator.uncached_checks += 1
            LinkValidator.cache[reference] = LinkStats(
                reference=reference, referencing_files=set([referencing_file])
            )
        result = LinkValidator.cache[reference].is_link_valid(referencing_file)

        # print(f"Total Checks: {LinkValidator.total_checks}, Percent Cached: {100*(1 - LinkValidator.uncached_checks / LinkValidator.total_checks):.2f}")

        if result is True:
            return True
        elif raise_exception_if_failure is True:
            raise (Exception(f"Reference Link Failed: {reference}"))
        else:
            return False

    @staticmethod
    def print_link_validation_errors():
        failures = [
            LinkValidator.cache[k]
            for k in LinkValidator.cache
            if LinkValidator.cache[k].valid is False
        ]
        failures.sort(key=lambda d: d.status_code)
        for failure in failures:
            print(
                f"Link {failure.reference} invalid with HTTP Status Code [{failure.status_code}] and referenced by the following files:"
            )
            for ref in failure.referencing_files:
                print(f"\t* {ref}")

    @staticmethod
    def SecurityContentObject_validate_references(v: list, values: dict) -> list:
        if "check_references" not in values:
            raise (Exception("Member 'check_references' missing from Baseline!"))
        elif values["check_references"] is False:
            # Reference checking is enabled
            pass
        elif values["check_references"] is True:
            for reference in v:
                LinkValidator.validate_reference(reference, values["name"])
                # Remove the check_references key from the values dict so that it is not
        # output by the serialization code
        del values["check_references"]

        return v
