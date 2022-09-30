import requests
import urllib3, urllib3.exceptions


DEFAULT_USER_AGENT_STRING = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36"
ALLOWED_HTTP_CODES = [200]
TIMEOUT_SEC = 15
ALLOW_REDIRECT = True
VERIFY_SSL = False


class LinkValidator:

    @staticmethod
    def check_references(references: list, name: str):
        for reference in references:
            try:
                get = requests.get(
                    reference, 
                    timeout=TIMEOUT_SEC, 
                    headers = {"User-Agent": DEFAULT_USER_AGENT_STRING}, 
                    allow_redirects=ALLOW_REDIRECT, 
                    verify=VERIFY_SSL
                )

                if get.status_code not in ALLOWED_HTTP_CODES:
                    print(get.status_code)
                    raise Exception(f"Reference Link Failed: {reference} for object {name}")
            

            except Exception as e:
                raise Exception(f"Reference Link Failed: {reference} for object {name}")