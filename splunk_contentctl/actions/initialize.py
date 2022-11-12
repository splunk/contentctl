'''
Initializes a Splunk Content Project
'''

from pathlib import Path
import yaml
import sys
import questionary
import os

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
    contentctl_config_path = Path(args.config)
    if contentctl_config_path.is_file():
        questions = [
            {
                'type': 'confirm',
                'message': 'File {0} already exist, are you sure you want to continue?\nTHIS WILL OVERWRITE YOUR CURRENT CONFIG!'.format(contentctl_config_path),
                'name': 'continue',
                'default': True,
            },
        ]

        answers = questionary.prompt(questions)
        if answers['continue']:
            print("> continuing with contentctl configuration...")
        else:
            print(
                "> exiting, to create a unique configuration file in another location use the --config flag")
            sys.exit(0)


    # configuration parameters    
    configpath = str(contentctl_config_path)

    # deal with skipping configuration
    if args.skip_configuration:
        print("initializing with default configuration: {0}".format(configpath))
        # write config file
        with open(configpath, 'w') as outfile:
            yaml.dump(default_config, outfile, default_flow_style=False, sort_keys=False)

        # write folder structure
        create_folders(args.output)
        

    questions = [
        {
            "type": "select",
            "message": "which build format should we use for this content pack? Builds will be created under the dist/ folder ",
            "name": "product",
            "choices": ["Splunk App", "JSON API Objects", "BA Objects", "All"],
            "default": "Splunk App"
        },

# should we deploy directly to a splunk server

# what is the default schedule for detections 

# what is the default action

# should we enrich mitre_attack_ids with tactics and actor group?

# should we enrich CVEs with a score and description when building

# are there any custom validators?

    ]

    answers = questionary.prompt(questions)

    # write config file
    with open(configpath, 'w') as outfile:
        yaml.dump(default_config, outfile, default_flow_style=False, sort_keys=False)

    # write folder structure
    create_folders(args.output)

        












