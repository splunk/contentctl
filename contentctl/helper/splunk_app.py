import json
from typing import Optional, Collection
from pathlib import Path
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

import requests
import urllib3
import xmltodict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_RETRY = 3


class APIEndPoint:
    """
    Class which contains Static Endpoint
    """

    SPLUNK_BASE_AUTH_URL = "https://splunkbase.splunk.com/api/account:login/"
    SPLUNK_BASE_FETCH_APP_BY_ENTRY_ID = (
        "https://apps.splunk.com/api/apps/entriesbyid/{app_name_id}"
    )
    SPLUNK_BASE_GET_UID_REDIRECT = "https://apps.splunk.com/apps/id/{app_name_id}"
    SPLUNK_BASE_APP_INFO = "https://splunkbase.splunk.com/api/v1/app/{app_uid}"


class RetryConstant:
    """
    Class which contains Retry Constant
    """

    RETRY_COUNT = 3
    RETRY_INTERVAL = 15


class SplunkBaseError(requests.HTTPError):
    """An error raise in communicating with Splunkbase"""
    pass


# TODO (PEX-306): validate w/ Splunkbase team if there are better APIs we can rely on being supported
class SplunkApp:
    """
    A Splunk app available for download on Splunkbase
    """

    class InitializationError(Exception):
        """An initialization error during SplunkApp setup"""
        pass

    @staticmethod
    def requests_retry_session(
        retries: int = RetryConstant.RETRY_COUNT,
        backoff_factor: int = 1,
        status_forcelist: Collection[int] = (500, 502, 503, 504),
        session: requests.Session | None = None,
    ) -> requests.Session:
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def __init__(
            self,
            app_uid: Optional[int] = None,
            app_name_id: Optional[str] = None,
            manual_setup: bool = False,
            ) -> None:
        if app_uid is None and app_name_id is None:
            raise SplunkApp.InitializationError(
                "Either app_uid (the numeric app UID e.g. 742) or app_name_id (the app name "
                "idenitifier e.g. Splunk_TA_windows) must be provided"
            )

        # init or declare instance vars
        self.app_uid: Optional[int] = app_uid
        self.app_name_id: Optional[str] = app_name_id
        self.manual_setup = manual_setup
        self.app_title: str
        self.latest_version: str
        self.latest_version_download_url: str
        self._app_info_cache: Optional[dict] = None

        # set instance vars as needed; skip if manual setup was indicated
        if not self.manual_setup:
            self.set_app_name_id()
            self.set_app_uid()
            self.set_app_title()
            self.set_latest_version_info()

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, SplunkApp):
            return self.app_uid == __value.app_uid
        return False

    def __repr__(self) -> str:
        return (
            f"SplunkApp(app_name_id='{self.app_name_id}', app_uid={self.app_uid}, "
            f"latest_version_download_url='{self.latest_version_download_url}')"
        )

    def __str__(self) -> str:
        return f"<'{self.app_name_id}' ({self.app_uid})"

    def get_app_info_by_uid(self) -> dict:
        """
        Retrieve app info via app_uid (e.g. 742)
        :return: dictionary of app info
        """
        # return cache if already set and raise and raise is app_uid is not set
        if self._app_info_cache is not None:
            return self._app_info_cache
        elif self.app_uid is None:
            raise SplunkApp.InitializationError("app_uid must be set in order to fetch app info")

        # NOTE: auth not required
        # Get app info by uid
        try:
            response = self.requests_retry_session().get(
                APIEndPoint.SPLUNK_BASE_APP_INFO.format(app_uid=self.app_uid),
                timeout=RetryConstant.RETRY_INTERVAL
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise SplunkBaseError(f"Error fetching app info for app_uid {self.app_uid}: {str(e)}")

        # parse JSON and set cache
        self._app_info_cache: dict = json.loads(response.content)

        return self._app_info_cache

    def set_app_name_id(self) -> None:
        """
        Set app_name_id
        """
        # return if app_name_id is already set
        if self.app_name_id is not None:
            return

        # get app info by app_uid
        app_info = self.get_app_info_by_uid()

        # set app_name_id if found
        if "appid" in app_info:
            self.app_name_id = app_info["appid"]
        else:
            raise SplunkBaseError(f"Invalid response from Splunkbase; missing key 'appid': {app_info}")

    def set_app_uid(self) -> None:
        """
        Set app_uid
        """
        # return if app_uid is already set and raise if app_name_id was not set
        if self.app_uid is not None:
            return
        elif self.app_name_id is None:
            raise SplunkApp.InitializationError("app_name_id must be set in order to fetch app_uid")

        # NOTE: auth not required
        # Get app_uid by app_name_id via a redirect
        try:
            response = self.requests_retry_session().get(
                APIEndPoint.SPLUNK_BASE_GET_UID_REDIRECT.format(app_name_id=self.app_name_id),
                allow_redirects=False,
                timeout=RetryConstant.RETRY_INTERVAL
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise SplunkBaseError(f"Error fetching app_uid for app_name_id '{self.app_name_id}': {str(e)}")

        # Extract the app_uid from the redirect path
        if "Location" in response.headers:
            self.app_uid = response.headers.split("/")[-1]
        else:
            raise SplunkBaseError(
                "Invalid response from Splunkbase; missing 'Location' in redirect header"
            )

    def set_app_title(self) -> None:
        """
        Set app_title
        """
        # get app info by app_uid
        app_info = self.get_app_info_by_uid()

        # set app_title if found
        if "title" in app_info:
            self.app_title = app_info["title"]
        else:
            raise SplunkBaseError(f"Invalid response from Splunkbase; missing key 'title': {app_info}")

    def __fetch_url_latest_version_info(self) -> str:
        """
        Identify latest version of the app and return a URL pointing to download info for the build
        :return: url for download info on the latest build
        """
        # retrieve app entries using the app_name_id
        try:
            response = self.requests_retry_session().get(
                APIEndPoint.SPLUNK_BASE_FETCH_APP_BY_ENTRY_ID.format(app_name_id=self.app_name_id),
                timeout=RetryConstant.RETRY_INTERVAL
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise SplunkBaseError(f"Error fetching app entries for app_name_id '{self.app_name_id}': {str(e)}")

        # parse xml
        app_xml = xmltodict.parse(response.content)

        # convert to list if only one entry exists
        app_entries = app_xml.get("feed").get("entry")
        if not isinstance(app_entries, list):
            app_entries = [app_entries]

        # iterate over multiple entries if present
        for entry in app_entries:
            for key in entry.get("content").get("s:dict").get("s:key"):
                if key.get("@name") == "islatest" and key.get("#text") == "True":
                    return entry.get("link").get("@href")

        # raise if no entry was found
        raise SplunkBaseError(f"No app entry found with 'islatest' tag set to True: {self.app_name_id}")

    def __fetch_url_latest_version_download(self, info_url: str) -> str:
        """
        Fetch the download URL via the provided URL to build info
        :param info_url: URL for download info for the latest build
        :return: URL for downloading the latest build
        """
        # fetch download info
        try:
            response = self.requests_retry_session().get(info_url, timeout=RetryConstant.RETRY_INTERVAL)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise SplunkBaseError(f"Error fetching download info for app_name_id '{self.app_name_id}': {str(e)}")

        # parse XML and extract download URL
        build_xml = xmltodict.parse(response.content)
        download_url = build_xml.get("feed").get("entry").get("link").get("@href")
        return download_url

    def set_latest_version_info(self) -> None:
        # raise if app_name_id not set
        if self.app_name_id is None:
            raise SplunkApp.InitializationError("app_name_id must be set in order to fetch latest version info")

        # fetch the info URL
        info_url = self.__fetch_url_latest_version_info()

        # parse out the version number and fetch the download URL
        self.latest_version = info_url.split("/")[-1]
        self.latest_version_download_url = self.__fetch_url_latest_version_download(info_url)

    def __get_splunk_base_session_token(self, username: str, password: str) -> str:
        """
        This method will generate Splunk base session token

        :param username: Splunkbase username
        :type username: str
        :param password: Splunkbase password
        :type password: str

        :return: Splunk base session token
        :rtype: str
        """
        # Data payload for fetch splunk base session token
        payload = urlencode(
            {
                "username": username,
                "password": password,
            }
        )

        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache",
        }

        response = requests.request(
            "POST",
            APIEndPoint.SPLUNK_BASE_AUTH_URL,
            data=payload,
            headers=headers,
        )

        token_value = ""

        if response.status_code != 200:
            msg = (
                f"Error occurred while executing the rest call for splunk base authentication api,"
                f"{response.content}"
            )
            raise Exception(msg)
        else:
            root = ET.fromstring(response.content)
            token_value = root.find("{http://www.w3.org/2005/Atom}id").text.strip()
        return token_value

    def download(
            self,
            out: Path,
            username: str,
            password: str,
            is_dir: bool = False,
            overwrite: bool = False
    ) -> Path:
        """
        Given an output path, download the app to the specified location

        :param out: the Path to download the app to
        :type out: :class:`pathlib.Path`
        :param username: Splunkbase username
        :type username: str
        :param password: Splunkbase password
        :type password: str
        :param is_dir: a flag indicating whether out is directory, otherwise a file (default: False)
        :type is_dir: bool
        :param overwrite: a flag indicating whether we can overwrite the file at out or not
        :type overwrite: bool

        :returns path: the Path the download was written to (needed when is_dir is True)
        :rtype: :class:`pathlib.Path`
        """
        # Get the Splunkbase session token
        token = self.__get_splunk_base_session_token(username, password)
        response = requests.request(
            "GET",
            self.latest_version_download_url,
            cookies={
                "sessionid": token
            }
        )

        # If the provided output path was a directory we need to try and pull the filename from the
        # response headers
        if is_dir:
            try:
                # Pull 'Content-Disposition' from the headers
                content_disposition: str = response.headers['Content-Disposition']

                # Attempt to parse the filename as a KV
                key, value = content_disposition.strip().split("=")
                if key != "attachment;filename":
                    raise ValueError(f"Unexpected key in 'Content-Disposition' KV pair: {key}")

                # Validate the filename is the expected .tgz file
                filename = Path(value.strip().strip('"'))
                if filename.suffixes != [".tgz"]:
                    raise ValueError(f"Filename has unexpected extension(s): {filename.suffixes}")
                out = Path(out, filename)
            except KeyError as e:
                raise KeyError(
                    f"Unable to properly extract 'Content-Disposition' from response headers: {e}"
                ) from e
            except ValueError as e:
                raise ValueError(
                    f"Unable to parse filename from 'Content-Disposition' header: {e}"
                ) from e

        # Ensure the output path is not already occupied
        if out.exists() and not overwrite:
            msg = (
                f"File already exists at {out}, cannot download the app."
            )
            raise Exception(msg)

        # Make any parent directories as needed
        out.parent.mkdir(parents=True, exist_ok=True)

        # Check for HTTP errors
        if response.status_code != 200:
            msg = (
                f"Error occurred while executing the rest call for splunk base authentication api,"
                f"{response.content}"
            )
            raise Exception(msg)

        # Write the app to disk
        with open(out, "wb") as file:
            file.write(response.content)

        return out
