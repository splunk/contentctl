'''
Initializes a Splunk Content Project
'''

from pathlib import Path
import yaml
import sys
import questionary
import os
from contentctl.objects.enums import LogLevel

import abc
from pydantic import BaseModel, Field

from contentctl.objects.config import Config

DEFAULT_FOLDERS = ['detections', 'stories', 'lookups', 'macros', 'baselines', 'dist']


def create_folders(path):

    for folder in DEFAULT_FOLDERS:
        folder_path = path + "/" + folder
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)



def NewContentPack(args, default_config):
    """
    new function creates a new configuration file based on the user input on the terminal.
    :param config: python dictionary having the configuration 
    :return: No return value
    """
    contentctl_config_file = Path(args.config)
    if contentctl_config_file.is_file():
        questions = [
            {
                'type': 'confirm',
                'message': 'File {0} already exist, are you sure you want to continue?\nTHIS WILL OVERWRITE YOUR CURRENT CONFIG!'.format(contentctl_config_file),
                'name': 'continue',
                'default': True,
            },
        ]

        answers = questionary.prompt(questions)
        if answers['continue']:
            print("> continuing with contentctl configuration...")
        else:
            print("> exiting, to create a unique configuration file in another location use the --config flag")
            sys.exit(0)


    # configuration parameters  
    if os.path.exists(args.output):  
        config_path = args.output + "/" + str(contentctl_config_file)
    else:
        print("ERROR, output folder: {0} does not exist".format(args.output))
        sys.exit(1)

    # deal with skipping configuration
    if args.skip_configuration:
        print("initializing with default configuration: {0}".format(config_path))
        # write config file
        with open(config_path, 'w') as outfile:
            yaml.dump(default_config, outfile, default_flow_style=False, sort_keys=False)

        # write folder structure
        create_folders(args.output)
        sys.exit(0)
        

    questions = [
        {
            "type": "select",
            "message": "Which build format should we use for this content pack? Builds will be created under the dist/ folder.",
            "name": "product",
            "choices": ["Splunk App", "JSON API Objects", "BA Objects", "All"],
            "default": "Splunk App"
        },
        {
            'type': 'text',
            'message': 'What should the Splunk App for this content pack be called?',
            'name': 'product_app_name',
            'default': 'Capybara Splunk Content Pack',
            'when': lambda answers: answers['product'] == "Splunk App" or answers['product'] == "All",

        },
        {
            'type': 'confirm',
            'message': 'Should this content pack be deployed to a (Cloud) Splunk Enterprise Server?',
            'name': 'deploy_to_splunk',
            'default': False,

        },
        {
            'type': 'text',
            'message': 'What is the <host>:<port> of the (Cloud) Splunk Enterprise Server?',
            'name': 'deploy_to_splunk_server',
            'default': '127.0.0.1:8089',
            'when': lambda answers: answers['deploy_to_splunk'],

        },
        {
            'type': 'text',
            'message': 'What is the username of the (Cloud) Splunk Enterprise Server?',
            'name': 'deploy_to_splunk_username',
            'default': 'admin',
            'when': lambda answers: answers['deploy_to_splunk'],

        },
        {
            'type': 'text',
            'message': 'What is the password of the (Cloud) Splunk Enterprise Server?',
            'name': 'deploy_to_splunk_password',
            'default': 'xxx',
            'when': lambda answers: answers['deploy_to_splunk'],

        },    
        {
            'type': 'text',
            'message': 'How often should analytics run? The schedule is on cron format (https://crontab.guru/).',
            'name': 'scheduling_cron_schedule',
            'default': '0 * * * *',
        },
        {
            'type': 'text',
            'message': 'What is the earliest time for analytics? Uses Splunk time modifiers (https://docs.splunk.com/Documentation/SCS/current/Search/Timemodifiers).',
            'name': 'scheduling_earliest_time',
            'default': '-70m@m',
        },
        {
            'type': 'text',
            'message': 'What is the latest time for analytics? Uses Splunk time modifiers (https://docs.splunk.com/Documentation/SCS/current/Search/Timemodifiers).',
            'name': 'scheduling_latest_time',
            'default': '-10m@m',
        },
        {
            'type': 'checkbox',
            'message': 'What should the default action be when an analytic triggers?',
            'name': 'default_actions',
            'choices': ["notable", "risk_event", "email"],
            'default': 'notable',
        },
        {
            'type': 'text',
            'message': 'What email address should we send the alerts to?',
            'name': 'to_email',
            'default': 'geralt@monsterkiller.com',
            'when': lambda answers: 'email' in answers['default_actions'],
        },
        {
            'type': 'confirm',
            'message': 'Should we include some example content? This will add a detection and its test with supporting components like lookups and macros.',
            'name': 'pre_populate',
            'default': True,
        },
    ]

    answers = questionary.prompt(questions)

    # create a custom config object to store answers
    custom_config = default_config

    # remove other product settings
    if answers['product'] == 'Splunk App':
        # pop other configs out
        custom_config['build'].pop('json_objects')
        custom_config['build'].pop('ba_objects')
        # capture configs
        custom_config['build']['splunk_app']['name'] = answers['product_app_name']
        custom_config['build']['splunk_app']['path'] = 'dist/' + answers['product_app_name'].lower().replace(" ", "_")
        custom_config['build']['splunk_app']['prefix'] = answers['product_app_name'].upper()[0: 3]

    elif answers['product'] == 'JSON API Objects':
        custom_config['build'].pop('splunk_app')
        custom_config['build'].pop('ba_objects')
    elif answers['product'] == 'BA Objects':
        custom_config['build'].pop('splunk_app')
        custom_config['build'].pop('json_objects')
    else:
        # splunk app config
        custom_config['build']['splunk_app']['name'] = answers['product_app_name']
        custom_config['build']['splunk_app']['path'] = 'dist/' + answers['product_app_name'].lower().replace(" ", "_")
        custom_config['build']['splunk_app']['prefix'] = answers['product_app_name'].upper()[0: 3]

    if answers['deploy_to_splunk']:
        custom_config['deploy']['server'] = answers['deploy_to_splunk_server']
        custom_config['deploy']['username'] = answers['deploy_to_splunk_username']
        custom_config['deploy']['password'] = answers['deploy_to_splunk_password']
    else:
        custom_config.pop('deploy')
    
    custom_config['scheduling']['cron_schedule'] = answers['scheduling_cron_schedule']
    custom_config['scheduling']['earliest_time'] = answers['scheduling_earliest_time']
    custom_config['scheduling']['latest_time'] = answers['scheduling_latest_time']

    if 'notable' in answers['default_actions']:
            custom_config['alert_actions']['notable']['rule_description'] = '%description%'
            custom_config['alert_actions']['notable']['rule_title'] = '%name%'
            custom_config['alert_actions']['notable']['nes_fields'] = ['user','dest','src']
    else:
        custom_config['alert_actions'].pop('notable')
    if 'risk_event' in answers['default_actions']:
            rba = dict()
            custom_config['alert_actions']['rba'] = rba
            custom_config['alert_actions']['rba']['enabled'] = 'true'
            
    if 'email' in answers['default_actions']:
            email = dict()
            custom_config['alert_actions']['email'] = email
            custom_config['alert_actions']['email']['subject'] = 'Alert %name% triggered'
            custom_config['alert_actions']['email']['message'] = 'The rule %name% triggered base on %description%'
            custom_config['alert_actions']['email']['to'] = answers['to_email']
        
   
    # write config file
    with open(config_path, 'w') as outfile:
        yaml.dump(custom_config, outfile, default_flow_style=False, sort_keys=False)
    print('Content pack configuration created under: {0} .. edit to fine tune details before building'.format(config_path))

    # write folder structure
    create_folders(args.output)
    print('The following folders were created: {0} under {1}.\nContent pack has been initialized, please run `new` to create new content.'.format(DEFAULT_FOLDERS, args.output))

    print("Load the custom_config into the pydantic model we have created")
    cfg = ContentPackConfig().parse_obj(custom_config)
    import pprint
    pprint.pprint(cfg.__dict__)
    print("********************")
    pprint.pprint(custom_config)
    print("done")
        












