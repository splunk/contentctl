from typing import Optional

from contentctl.objects.test_config import Infrastructure
from contentctl.objects.base_test_result import BaseTestResult


SAVED_SEARCH_TEMPLATE = "{server}:{web_port}/en-US/{path}"


class IntegrationTestResult(BaseTestResult):
    """
    An integration test result
    """
    # the total time we slept waiting for the detection to fire after activating it
    wait_duration: Optional[int] = None

    # the path to the saved search on the Splunk endpoint
    saved_search_path: Optional[str] = None

    def get_saved_search_url(self, infra: Infrastructure):
        """
        Given an Infrastructure config, return the link to the saved search (detection) we are
        testing
        :param infra: an Infrastructure config
        :returns: str, the URL to the saved search
        """
        # If the path was not set for some reason, just return the base URL
        path = ""
        if self.saved_search_path is not None:
            path = self.saved_search_path
        return SAVED_SEARCH_TEMPLATE.format(
                server=infra.instance_address,
                web_port=infra.web_ui_port,
                path=path,
            )
