from contentctl.objects.config import deploy_acs, StackType
from requests import post
import pprint


class Deploy:
    def execute(self, config: deploy_acs, appinspect_token:str) -> None:
        
        #The following common headers are used by both Clasic and Victoria
        headers = {
            'Authorization': f'Bearer {config.splunk_cloud_jwt_token}',
            'ACS-Legal-Ack': 'Y'
        }
        try:
            
            with open(config.getPackageFilePath(include_version=False),'rb') as app_data:
                #request_data = app_data.read()
                if config.stack_type == StackType.classic:
                    # Classic instead uses a form to store token and package
                    # https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps#Manage_private_apps_using_the_ACS_API_on_Classic_Experience
                    address = f"https://admin.splunk.com/{config.splunk_cloud_stack}/adminconfig/v2/apps"
                    
                    form_data = {
                        'token': (None, appinspect_token),
                        'package': app_data
                    }
                    res = post(address, headers=headers, files = form_data)
                elif config.stack_type == StackType.victoria:
                    # Victoria uses the X-Splunk-Authorization Header
                    # It also uses --data-binary for the app content
                    # https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Config/ManageApps#Manage_private_apps_using_the_ACS_API_on_Victoria_Experience
                    headers.update({'X-Splunk-Authorization':  appinspect_token})
                    address = f"https://admin.splunk.com/{config.splunk_cloud_stack}/adminconfig/v2/apps/victoria"
                    res = post(address, headers=headers, data=app_data.read())
                else:
                    raise Exception(f"Unsupported stack type: '{config.stack_type}'")
        except Exception as e:
            raise Exception(f"Error installing to stack '{config.splunk_cloud_stack}' (stack_type='{config.stack_type}') via ACS:\n{str(e)}")
        
        try:
            # Request went through and completed, but may have returned a non-successful error code.
            # This likely includes a more verbose response describing the error
            res.raise_for_status()
            print(res.json())
        except Exception as e:
            try:
                error_text = res.json()
            except Exception as e:
                error_text = "No error text - request failed"
            formatted_error_text = pprint.pformat(error_text)
            print("While this may not be the cause of your error, ensure that the uid and appid of your Private App does not exist in Splunkbase\n"
                  "ACS cannot deploy and app with the same uid or appid as one that exists in Splunkbase.")
            raise Exception(f"Error installing to stack '{config.splunk_cloud_stack}' (stack_type='{config.stack_type}') via ACS:\n{formatted_error_text}")
        
        print(f"'{config.getPackageFilePath(include_version=False)}' successfully installed to stack '{config.splunk_cloud_stack}' (stack_type='{config.stack_type}') via ACS!")