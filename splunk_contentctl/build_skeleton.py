from distutils.command.build import build
from io import TextIOWrapper
import json
import pathlib
import os
from posixpath import relpath
import sys
from threading import main_thread
from venv import create
import questionary
import shutil
from typing import Any
import copy
import hierarchy_schema
import jsonschema
from typing import Union, Tuple
import jinja2
import art.ascii_art
import splunkbase_enumerator
import git
from external_libraries.download_splunkbase import download_splunkbase

DEFAULT_HIERARCHY_FILE = pathlib.Path("folder_hierarchy.json")
DEFAULT_SECURITY_CONTENT_ROOT = pathlib.Path() 
JINJA2_TEMPLATE_EXTENSION = ".j2"
SPLUNKBASE_UI_APP_URL = "https://splunkbase.splunk.com/app/{uid}/"

def printAtDepth(value:str, depth:int, indent:str='   ')->None:
    indentation = indent * depth
    print(f"{indentation}{value}")

def process_folder(root:dict, source_path: pathlib.Path, dest_path:pathlib.Path, force_defaults:bool=False, mock:bool=False)->bool:
    required = root['required']
    mode = root['mode']
    
    if required:
        # Note that mode COPY CAN lead to a case where we copy a root folder,
        # then recursive into a subfolder and the user chooses not to copy 
        # the contents of that folder. Those contents may still exist
        # if those contents came from the donor_app.  We need it to work
        # this way because the contents may come from the donor_app or
        # they may be an entirely new folder/file.
        if mode == "copy":
            if mock is False:
                shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
            return False
        elif mode == "create":
            if mock is False:
                dest_path.mkdir(parents=True, exist_ok=True)
        else:
            raise(Exception(f"Unsupported mode for folder [{mode}]"))
        return True
    else:
        if force_defaults is False:
            answer = questionary.confirm(f"{root['description']}\n{os.path.relpath(dest_path)} - Copy contents?").ask()
        else:
            answer=required
        if answer is True:
            root['required'] = True
            return process_folder(root, source_path, dest_path, force_defaults, mock)
        elif answer is False:
            #At the very least the folder will be created
            if mock is False:
                dest_path.mkdir(parents=True, exist_ok=True)

            #Just don't do anything
            return False
        else:
            #This will occur if the user CTRL-C (or otherwise stops) the process
            #we will exit from the tool with a nonzero code
            print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
            sys.exit(1)
        




    
def process_file(root:dict, source_path: pathlib.Path, dest_path:pathlib.Path, force_defaults:bool=False, mock:bool=False)->bool:
    required = root['required']
    mode = root['mode']

    if required:
        if mock is True:
            return True
        if mode == "copy":
            shutil.copyfile(source_path, dest_path)
        else:
            raise(Exception(f"Unsupported mode for file [{root['mode']}]. Only 'copy' is supported."))
        return True
    else:
        if force_defaults is False:
            answer = questionary.confirm(f"{root['description']}\n{os.path.relpath(dest_path)} - Copy file?").ask()
        else:
            answer = required
        if answer is True:
            root['required'] = True
            return process_file(root, source_path, dest_path, force_defaults, mock)
        elif answer is False:
            return False
        else:
            #This will occur if the user CTRL-C (or otherwise stops) the process
            #we will exit from the tool with a nonzero code
            print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
            sys.exit(1)

def process_template(root:dict, source_path: pathlib.Path, original_template_filename:pathlib.Path, answers:dict[str,Any], force_defaults:bool=False, mock:bool=False)->bool:
    required = root['required']

    if str(original_template_filename).endswith(JINJA2_TEMPLATE_EXTENSION):
        updated_file_name = pathlib.Path(str(original_template_filename)[:-len(JINJA2_TEMPLATE_EXTENSION)]) #trims off the .j2 at the end
    else:
        raise(Exception(f"Jinja2 template file {original_template_filename} does not end with {JINJA2_TEMPLATE_EXTENSION}"))

    if required:
        if mock:
            #Don't do anything
            return True


        with open(source_path, 'r') as template_file, open(updated_file_name,'w') as tgt:
            template = jinja2.Template(template_file.read())
            tgt.write(template.render(answers))
        
        try:
            #delete the jinja2 template which MAY have been copied to this directory if
            #a parent operation copied a whole directory
            os.remove(original_template_filename)
            
        except FileNotFoundError as e:
            #It's okay if the file doesn't exist, in most cases it won't have been copied
            #into the directory
            pass
        except Exception as e:
            raise(Exception(f"Error removing Jinja2 Template file {original_template_filename}: {str(e)}"))
     
    else:
        if force_defaults is False:
            answer = questionary.confirm(f"{root['description']}\n{os.path.relpath(updated_file_name)} - Create template?").ask()
        else:
            answer = required
        if answer is True:
            root['required'] = True
            return process_template(root, source_path, original_template_filename, answers, force_defaults, mock)
        elif answer is False:
            return False
        else:
            #This will occur if the user CTRL-C (or otherwise stops) the process
            #we will exit from the tool with a nonzero code
            print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
            sys.exit(1)
        
    return True

def create_structure(root:dict, source_path:pathlib.Path, target_path:pathlib.Path, mainAnswers: dict[str,Any], force_defaults:bool=False, mock:bool=False):
    
    #There is a chance that the target name was dynamic. In that case,
    #we must make sure that we create the object with the correct name
    #based on an answer provided in the questions
    if 'target_name' in root:
        #This is a path that needs a different name than 
        #the donor app.  This could be a static name or a name
        #that is equal to one of the answers
        
        #This is the name of the app, so update that
        root['target_name'] = mainAnswers['APP_NAME']

        target_path = pathlib.Path(os.path.join(target_path,root['target_name']))
    else:
        #There is not target_name, so just use the name in the file as normal
        target_path = pathlib.Path(os.path.join(target_path,root['name']))    
    

    
    
    source_path = pathlib.Path(os.path.join(str(source_path), root['name']))
    
    
    if root['type'] == "folder":
        create_children = process_folder(root, source_path, target_path, force_defaults, mock)
    elif root['type'] == "file":
        create_children = process_file(root, source_path, target_path, force_defaults, mock)
        
    elif root['type'] == "template":
        #Trim off the .j2 extension from the end of the file
        create_children = process_template(root, source_path, target_path, mainAnswers, force_defaults, mock)

        
    else:
        raise(Exception(f"Unsupported type: [{root['type']}]"))

    
    force_defaults = force_defaults or (not create_children)
    for child in root['children']:
        create_structure(child, source_path, target_path, mainAnswers,force_defaults, mock)
    
    
    
def git_init_remote_repo(answers:dict):
    repo_path = os.path.join(answers['output_path'], answers['APP_NAME'])
    print(f"Pushing new repo to {answers['git_repo_target']} from source dir {repo_path}...", end='', flush=True)
    
    #Code in this block is fror pygit
    try:
        bare_repo = git.Repo.init(repo_path, bare=False, b=answers['git_main_branch'])
    except Exception as e:
        raise(Exception(f"Error initializing repo: {str(e)}"))
    try:
        bare_repo.git.add(all=True)
    except Exception as e:
        raise(Exception(f"Error adding new content to initial commit: {str(e)}"))
    try:
        bare_repo.git.commit("-m", f"Initialization of skeleton for new app {answers['APP_NAME']}")
    except Exception as e:
        raise(Exception(f"Error making first local commit to repo: {str(e)}"))
    try:
        bare_repo.git.remote("add", "origin", answers['git_repo_target'])
        bare_repo.git.remote("-v")
    except Exception as e:
        raise(Exception(f"Error adding remote origin for git repo: {str(e)}"))

    try:
        bare_repo.git.push("-u", "origin", answers['git_main_branch'])
    except Exception as e:
        raise(Exception(f"Error pushing first commit to remote repo.  Please verify that {answers['git_repo_target']} exists and you have the appropriate access and tokens loaded for this repo: {str(e)}"))
    print("done!")

def get_answers_to_questions(questions:list[dict], output_path:str, force_defaults:bool=False)->dict[str,str]:
    
    
    answers = {}

    for question in questions:
        #loop to keep retrying until we get a valid answer
        if 'jsonschema_validator' in question:
            validator = question['jsonschema_validator']
            question.pop('jsonschema_validator')
        else:
            validator = None
        
        while True:
            value_name = question['name']
            if value_name == "output_path":
                question['default'] = output_path
            if force_defaults is False:
                default = question['default']
                if default in answers:
                    question['default'] = answers[default]
                this_answer = questionary.prompt(question)
                if this_answer == {}:
                    #This will occur if the user CTRL-C (or otherwise stops) the process
                    #we will exit from the tool with a nonzero code
                    print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
                    sys.exit(1)


                        
                value = this_answer[value_name]
                if validator:
                    try:
                        jsonschema.validate(value, validator)
                    except jsonschema.ValidationError as e:
                        print(f"Answer '{value}' did not pass validation against the schema '{validator['pattern']}'. Try again.")
                        continue
                question['default'] = value
            

                answers.update(this_answer)
            else:
                answers.update({question['name']: question['default']})
            if validator:
                question['jsonschema_validator'] = validator
            break

    
    return answers

def ask_for_another_app(app_data:list[dict])->dict:
    descriptions = []
    releases = []
    
    for app in app_data:
        description = f"{app['title']} (appid: {app['appid']}, {SPLUNKBASE_UI_APP_URL.format(uid=app['uid'])})"
        release_list = app['releases']
        descriptions.append(description)
        releases.append(release_list)
    while True:
        ans = questionary.autocomplete("Type the name of an app to install", choices=descriptions).ask()
        if ans is not None:
            if ans in descriptions:
                break
            else:
                print(f"'{ans}' is not a valid choice. Please try again.")
            
        if ans is None:
            print("We will assume that Ctrl-C means you don't want to add an app.")
            return {}
    
    #Now print out the releases and let the user user
    whole_app = app_data[descriptions.index(ans)]
    release = questionary.select("Which release would you like to install (newest selected by default)", choices=whole_app['releases'], default=whole_app['releases'][0]).ask()
    if release is None:
        #This will occur if the user CTRL-C (or otherwise stops) the process
        #we will exit from the tool with a nonzero code
        print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
        sys.exit(1)        
    
    return {"uid":whole_app['uid'], "appid":whole_app["appid"], "title":whole_app['title'], "release":release}
    
    
    
def app_upgrade_available(app:dict, all_apps:list[dict])->Union[str,None]:
    
    full_app = get_app_by_appid(app['appid'],all_apps)
    if full_app['releases'][0] != app['release']:
        return full_app['releases'][0]
    else:
        return None




def get_apps_to_install(initial_apps:list[dict], force_refresh_app_data:bool=False, mock:bool=False)->list[dict]:
    apps_to_install = []
    all_apps = splunkbase_enumerator.get_all_app_data(force_refresh_app_data=force_refresh_app_data)

    if mock is False:
        for app in initial_apps:
            if app_upgrade_available(app, all_apps):
                print(f"{app['title']} upgrade available {app['release']}-->{app_upgrade_available(app, all_apps)}")
        return initial_apps

    if len(initial_apps) > 0:
        print(f"There are {len(initial_apps)} configured for installation.  Let's check each one.")
        for app in initial_apps:
            app_to_install = confirm_app_and_version(app,all_apps)
            if app_to_install == {}:
                continue
            apps_to_install.append(app_to_install)
    
    while True:
        more = questionary.confirm("Do you want to add apps to install?").ask()
        if more is True:
            another_app = ask_for_another_app(all_apps)
            if another_app == {}:
                return apps_to_install
            else:
                apps_to_install.append(another_app)
        elif more is False:
            return apps_to_install
        else:
            #This will occur if the user CTRL-C (or otherwise stops) the process
            #we will exit from the tool with a nonzero code
            print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
            sys.exit(1)   


def get_app_by_appid(appid:int, all_apps:list[dict])->dict:
    for app in all_apps:
        if app['appid'] == appid:
            return app
    raise(Exception(f"appid [{appid}] not found in list of apps from Splunkbase.  Are you sure it exists?"))



def confirm_app_and_version(app:dict, all_apps:list[dict])->dict:
    app_summary = f"{app['title']}, release: {app['release']} (appid: {app['appid']}, {SPLUNKBASE_UI_APP_URL.format(uid=app['uid'])})"
    full_app = get_app_by_appid(app['appid'], all_apps)

    
    if app['release'] != full_app['releases'][0]:
        print(f"There is a newer version of '{app['title']}' {app['release']}-->{full_app['releases'][0]}")
    
    if app['release'] not in full_app['releases']:
        print(f"Warning, the specified version {app['release']} does not exist in releases {full_app['releases']}. Defaulting to newest version {full_app['releases'][0]}")
        app['release'] = full_app['releases'][0]

    answer = questionary.confirm(f"{app_summary}\nInstall this app and version?").ask()
    if answer is True:
        #Now get the version of the app to install
        release = questionary.select("Which release would you like to install", choices=full_app['releases'], default=app['release']).ask()
        if release is None:
            #This will occur if the user CTRL-C (or otherwise stops) the process
            #we will exit from the tool with a nonzero code
            print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
            sys.exit(1)        
        return {"uid":app['uid'], "appid":app["appid"], "title":app['title'], "release":release}


    elif answer is False:
        #Empty dict means no app to install
        return {}
    else:
        #This will occur if the user CTRL-C (or otherwise stops) the process
        #we will exit from the tool with a nonzero code
        print("CTRL-C (or similar) detected... setup is not complete.  Exiting with nonzero status code")
        sys.exit(1)        


def init(args):

    input_template = args.template_object
    output_template = None
    mock=False
    args.force_defaults = True
    build_inquire(args, mock, input_template, output_template)

def configure(args):
    
    input_template = args.template_object
    output_template = args.output_file
    mock = True
    build_inquire(args, mock, input_template, output_template)

def build_inquire(args, mock:bool, input_template_data:dict, output_template:Union[TextIOWrapper,None]=None ):
    #Update this due to the way that argparse assigned the value top force_defaults argument
    if args.force_defaults is None:
        args.force_defaults = False

    if mock is True and output_template is None:
        raise(Exception(f"If mock is True, then an output_template MUST be provided"))
    
    
    print(art.ascii_art.header)
    if mock:
        print(art.ascii_art.configure)
    else:
        print(art.ascii_art.init)
    
    

    
    
    
    
    


    
    
    security_content_root = pathlib.Path(DEFAULT_SECURITY_CONTENT_ROOT)
    
    #Note that this function modifies the original json_data['questions'] dict
    
    answers = get_answers_to_questions(input_template_data['questions'], 
                                       args.template_answers['output_path'], 
                                       force_defaults=args.force_defaults)
    
    
    input_template_data['apps'] = get_apps_to_install(input_template_data['apps'], mock=mock)
    
    

    
    
    try:
    
        hierarchy = input_template_data['hierarchy'] 
        source_path = pathlib.Path(answers['donor_app_root'])
        output_path = pathlib.Path(answers['output_path'])
        create_structure(hierarchy, source_path, output_path, answers, force_defaults=args.force_defaults,mock=mock)
    except Exception as e:
        print(f"There was an exception creating the skeleton: {str(e)} ")
        sys.exit(1)
    
    
    if mock is True:
        if output_template is not None:
            json.dump(input_template_data, output_template, indent="    ")
            print(f"Wrote Custom Config File to {output_template.name}")
        else:
            raise(Exception(f"Output template was NONE, but MOCK was enabled, so an output template must be provided"))

    else:
        
        git_init_remote_repo(answers)
        apps = input_template_data['apps']
        output_app_path = pathlib.Path(os.path.join(answers['output_path'], answers['APP_NAME'],"apps"))
        download_all_splunkbase_apps(apps, output_app_path)

def download_all_splunkbase_apps(apps:list[dict], output_path:pathlib.Path):

    if not os.path.exists(output_path):
        os.makedirs(output_path)
        print(f"Created directory for storing apps: {output_path}")
    
    #Download all of the apps to the appointed directory
    try:
        #Make these questionary questions or command line.... but don't
        #allow them to be cached to a file
        username = input("username: ")
        password = input("password: ")
        download_splunkbase.download_all_apps(username, password, apps, output_path)
    except Exception as e:
        print(f"Error downloading app(s) from Splunkbase: {str(e)}")
        sys.exit(1)
    



    

