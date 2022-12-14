import os
import git
import shutil
import requests
import random
import string
from timeit import default_timer
import pathlib
import datetime
from typing import Union

from splunk_contentctl.objects.security_content_object import SecurityContentObject
TOTAL_BYTES = 0
TOTAL_DOWNLOAD_TIME = 0
ALWAYS_PULL = True





class Utils:

    @staticmethod
    def get_all_yml_files_from_directory(path: str) -> list:
        listOfFiles = list()
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                if file.endswith(".yml"):
                    listOfFiles.append(os.path.join(dirpath, file))
    
        return sorted(listOfFiles)

    @staticmethod
    def add_id(id_dict:dict[str, list[str]], obj:SecurityContentObject, path:str) -> None:     
        if hasattr(obj, "id"):
            obj_id = obj.id
            if obj_id in id_dict:
                id_dict[obj_id].append(path)
            else:
                id_dict[obj_id] = [path]
    # Otherwise, no ID so nothing to add....
     
    @staticmethod
    def check_ids_for_duplicates(id_dict:dict[str, list[str]])->bool:
        validation_error = False
        for key, values in id_dict.items():
            if len(values) > 1:
                validation_error = True
                id_conflicts_string = '\n\t* '.join(values)
                print(f"\nError validating id [{key}] - duplicate ID is used for the following content: \n\t* {id_conflicts_string}")
        return validation_error


    @staticmethod
    def validate_git_hash(repo_path:str, repo_url:str, commit_hash:str,  branch_name:Union[str,None])->bool:
        
        #Get a list of all branches
        repo = git.Repo(repo_path)
        if commit_hash is None:
            #No need to validate the hash, it was not supplied
            return True
                

        try:
            all_branches_containing_hash = repo.git.branch("--contains", commit_hash).split('\n')
            #this is a list of all branches that contain the hash.  They are in the format:
            #* <some number of spaces> branchname (if the branch contains the hash)
            #<some number of spaces>   branchname (if the branch does not contain the hash)
            #Note, of course, that a hash can be in 0, 1, more branches!
            for branch_string in all_branches_containing_hash:
                if branch_string.split(' ')[0] == "*" and (branch_string.split(' ')[-1] == branch_name or branch_name==None):
                    #Yes, the hash exists in the branch (or branch_name was None and it existed in at least one branch)!
                    return True
            #If we get here, it does not exist in the given branch
            raise(Exception("Does not exist in branch"))

        except Exception as e:
            if branch_name is None:
                branch_name = "ANY_BRANCH"
            if ALWAYS_PULL:
                raise(ValueError(f"hash '{commit_hash}' not found in '{branch_name}' for repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"))
            else:
                raise(ValueError(f"hash '{commit_hash}' not found in '{branch_name}' for repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"\
                                  "If the hash is new, try pulling the repo."))



    @staticmethod
    def get_default_branch_name(repo_path:str, repo_url:str)->str:
        #Even though the default branch is only a notion in GitHub or 
        #similar systems, we will consinder the default branch
        #to be the name of the branch that is the HEAD of the repo.
        #This means that it should work for ANY repo with a remote.
        
        repo = git.Repo(repo_path)
        
        #Only works for remotes!
        for remote in repo.remotes.origin.refs:
            if remote.name.endswith("/HEAD"):
                #return the name of this branch.  it will be prefixed with 'origin/', so remove the origin/
                return remote.ref.name.replace("origin/", "")
        raise(ValueError(f"Failed to find default branch in repo_path: {repo_path}\n  * repo_url: {repo_url}"))


    @staticmethod
    def validate_git_branch_name(repo_path:str, repo_url:str, name:str)->bool:
        #Get a list of all branches
        repo = git.Repo(repo_path)
        
        all_branches = [branch.name for branch in repo.refs]
        #remove "origin/" from the beginning of each branch name
        all_branches = [branch.replace("origin/","") for branch in all_branches]


        if name in all_branches:
            return True
        
        else:
            if ALWAYS_PULL:
                raise(ValueError(f"branch '{name}' not found in repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"))
            else:
                raise(ValueError(f"branch '{name}' not found in repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"\
                    "If the branch is new, try pulling the repo."))
        
        
        
    
    @staticmethod
    def validate_git_pull_request(repo_path:str, pr_number:int)->str:
        #Get a list of all branches
        repo = git.Repo(repo_path)
        #List of all remotes that match this format.  If the PR exists, we
        #should find exactly one in the format SHA_HASH\tpull/pr_number/head
        pr_and_hash = repo.git.ls_remote("origin", f"pull/{pr_number}/head")

        
        if len(pr_and_hash) == 0:
            raise(ValueError(f"pr_number {pr_number} not found in Remote '{repo.remote().url}'"))

        pr_and_hash_lines = pr_and_hash.split('\n')
        if len(pr_and_hash_lines) > 1:
            raise(ValueError(f"Somehow, more than 1 PR was found with pr_number {pr_number}:\n{pr_and_hash}\nThis should not happen."))

                
        if pr_and_hash_lines[0].count('\t')==1:
            hash, _ = pr_and_hash_lines[0].split('\t') 
            return hash
        else:
            raise(ValueError(f"Expected PR Format:\nCOMMIT_HASH\tpull/{pr_number}/head\nbut got\n{pr_and_hash_lines[0]}"))
            
        return hash

    @staticmethod
    def check_required_fields(thisField:str, definedFields:dict, requiredFields:list[str]):
        missing_fields = [field for field in requiredFields if field not in definedFields]
        if len(missing_fields) > 0:
            raise(ValueError(f"Could not validate - please resolve other errors resulting in missing fields {missing_fields}"))

    

    @staticmethod
    def verify_file_exists(file_path:str, verbose_print=False, timeout_seconds:int = 10)->None:
        
        try:
            if pathlib.Path(file_path).is_file():
                #This is a file and we know it exists
                return None
        except Exception as e:
            print(f"Could not copy local file {file_path} the file because {str(e)}")


        
        #Try to make a head request to verify existence of the file
        try:
            req = requests.head(file_path, timeout=timeout_seconds, verify=True, allow_redirects=True)
            if req.status_code > 400:
                raise(Exception(f"Return code {req.status_code}"))
        except Exception as e:
            raise(Exception(f"Cannot confirm the existence of '{file_path}' - are you sure it exists: {str(e)}"))     
        
            

    @staticmethod
    def download_file_from_http(file_path:str, destination_file:str, overwrite_file:bool=False, chunk_size:int=1024*1024, verbose_print:bool=False)->None:
        global TOTAL_BYTES, TOTAL_DOWNLOAD_TIME
        
        try:
            #generates an exception only if the copyfile fails.
            #if we try this with a URL, it won't be found as a file and no
            #exception will be generated
            if pathlib.Path(file_path).is_file():
                shutil.copyfile(file_path, destination_file)
                return
        except Exception as e:
            print(f"Could not copy local file {file_path} the file because {str(e)}")

        
        if os.path.exists(destination_file) and overwrite_file is False:
            print(f"[{destination_file}] already exists...using cached version")
            return
        if verbose_print:
            print(f"downloading to [{destination_file}]...",end="", flush=True)
        try:
            download_start_time = default_timer()
            bytes_written=0
            file_to_download = requests.get(file_path, stream=True)
            if file_to_download.status_code != 200:
                if verbose_print:
                    print("FAILED")
                raise Exception(f"Error downloading the file {file_path}: Status Code {file_to_download.status_code}")
            with open(destination_file, "wb") as output:
                for piece in file_to_download.iter_content(chunk_size=chunk_size):
                    bytes_written += output.write(piece)
            if verbose_print:
                print("Done")
            download_stop_time = default_timer()
            timedelta = download_stop_time-download_start_time
            TOTAL_BYTES += bytes_written
            TOTAL_DOWNLOAD_TIME += timedelta
            
        except Exception as e:
            if verbose_print:
                print("FAILED")
            raise e
        return

    @staticmethod
    def print_total_download_stats()->None:
        
        time_string = datetime.timedelta(seconds=round(TOTAL_DOWNLOAD_TIME))
        print(f"Download statistics:\n"
            f"\tTotal MB     :{(TOTAL_BYTES/(1024*1024)):.0f}MB\n"
            f"\tTotal Seconds:{time_string}s")

    # taken from attack_range
    @staticmethod
    def get_random_password(password_min_length: int = 16, password_max_length: int = 26) -> str:
        random_source = string.ascii_letters + string.digits
        password = random.choice(string.ascii_lowercase)
        password += random.choice(string.ascii_uppercase)
        password += random.choice(string.digits)

        for i in range(random.randrange(password_min_length, password_max_length)):
            password += random.choice(random_source)

        password_list = list(password)
        random.SystemRandom().shuffle(password_list)
        password = "".join(password_list)
        return password
    
    @staticmethod
    def warning_print(msg:str, prefix:str = "MESSAGE TO CONTENTCTL DEV", suppress=False):
        if not suppress:
            print(f"{prefix}: {msg}")