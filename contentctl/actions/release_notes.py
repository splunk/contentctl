import os

from dataclasses import dataclass

from contentctl.input.director import DirectorInputDto, Director, DirectorOutputDto
from contentctl.output.svg_output import SvgOutput
from contentctl.output.attack_nav_output import AttackNavOutput
from git import Repo
import re
import yaml
from typing import Union


@dataclass(frozen=True)
class ReleaseNotesInputDto:
    director_input_dto: DirectorInputDto

class ReleaseNotes:
    def create_notes(self,repo_path, file_paths):
            for file_path in file_paths:
                # Check if the file exists
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    # Check if the file is a YAML file
                    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                        # Read and parse the YAML file
                        with open(file_path, 'r') as file:
                            try:
                                data = yaml.safe_load(file)
                                # Check and create story link
                                if 'name' in data and 'stories/' in file_path:
                                    story_link = "https://research.splunk.com/stories/" + data['name']
                                    story_link=story_link.replace(" ","_")
                                    story_link=story_link.replace("- ","_")
                                    story_link = story_link.lower()
                                    print("- "+"["+f"{data['name']}"+"]"+"("+story_link+")")
                                # Check and create detection link
                                if 'name' in data and 'id' in data and 'detections/' in file_path:
                                    temp_link = "https://research.splunk.com" + file_path.replace(repo_path,"")
                                    pattern = r'(?<=/)[^/]*$'
                                    detection_link = re.sub(pattern, data['id'], temp_link)
                                    detection_link = detection_link.replace("detections","" )
                                    detection_link = detection_link.replace(".com//",".com/" )
                                    print("- "+"["+f"{data['name']}"+"]"+"("+detection_link+")")    
                                if 'name' in data and'playbooks/' in file_path:
                                    playbook_link = "https://research.splunk.com" + file_path.replace(repo_path,"")
                                    playbook_link=playbook_link.replace(".yml","/").lower()
                                    print("- "+"["+f"{data['name']}"+"]"+"("+playbook_link+")")

                                if 'name' in data and'macros/' in file_path:
                                    print("- " + f"{data['name']}")

                                if 'name' in data and'lookups/' in file_path:
                                    print("- " + f"{data['name']}")

                            except yaml.YAMLError as exc:
                                print(f"Error parsing YAML file {file_path}: {exc}")
                else:
                    print(f"File not found or is not a file: {file_path}")

    def release_notes(self, input_dto: DirectorInputDto, old_tag:Union[str,None], new_tag:str, latest_branch:str) -> None:

        ### Remove hard coded path
        directories = ['detections/','stories/','macros/','lookups/','playbooks']
        repo_path = os.path.abspath(input_dto.director_input_dto.input_path)
        repo = Repo(repo_path)
        # Ensure the new tag is in the tags if tags are supplied
      
        if new_tag:    
            if new_tag not in repo.tags:
                raise ValueError(f"new_tag {new_tag} does not exist in the repository. Make sure your branch nameis ")
            if old_tag is None:
                #Old tag was not supplied, so find the index of the new tag, then get the tag before it
                tags_sorted = sorted(repo.tags, key=lambda t: t.commit.committed_datetime, reverse=True)
                tags_names_sorted = [tag.name for tag in tags_sorted]            
                new_tag_index = tags_names_sorted.index(new_tag)
                try:
                    old_tag = tags_names_sorted[new_tag_index+1]
                except Exception:
                    raise ValueError(f"old_tag cannot be inferred.  {new_tag} is the oldest tag in the repo!")   
            latest_tag = new_tag
            previous_tag = old_tag   
            commit1 = repo.commit(latest_tag)
            commit2 = repo.commit(previous_tag)       
            diff_index = commit2.diff(commit1)

        # Ensure the branch is in the repo          
        if latest_branch:
            #If a branch name is supplied, compare against develop
            if latest_branch not in repo.branches:
                raise ValueError(f"latest branch {latest_branch} does not exist in the repository. Make sure your branch name is correct")
            latest_branch = latest_branch
            compare_against = "develop"
            commit1 = repo.commit(latest_branch)
            commit2 = repo.commit(compare_against)    
            diff_index = commit2.diff(commit1)
        
        modified_files = []
        added_files = []
        for diff in diff_index:
            file_path = diff.a_path

            # Check if the file is in the specified directories
            if any(file_path.startswith(directory) for directory in directories):
                # Check if a file is Modified
                if diff.change_type == 'M':
                    modified_files.append(file_path)
                # Check if a file is Added
                elif diff.change_type == 'A':
                    added_files.append(file_path)
                    # print(added_files)

        detections_added = []
        stories_added = []
        macros_added = []
        lookups_added = []
        playbooks_added = []      
        detections_modified = []
        stories_modified = []
        macros_modified = []
        lookups_modified = []
        playbooks_modified = []

        for file in modified_files:
            file=repo_path +"/"+file
            if 'detections/' in file:
                detections_modified.append(file)
            if 'stories/' in file:
                stories_modified.append(file)
            if 'macros/' in file:
                macros_modified.append(file)
            if 'lookups/' in file:
                lookups_modified.append(file)
            if 'playbooks/' in file:
                playbooks_modified.append(file)

        for file in added_files:
            file=repo_path +"/"+file
            if 'detections/' in file:
                detections_added.append(file)
            if 'stories/' in file:
                stories_added.append(file)
            if 'macros/' in file:
                macros_added.append(file)
            if 'lookups/' in file:
                lookups_added.append(file)
            if 'playbooks/' in file:
                playbooks_added.append(file)
        if new_tag:

            print(f"Generating release notes       - \033[92m{latest_tag}\033[0m")
            print(f"Compared against               - \033[92m{previous_tag}\033[0m")
            print("\n## Release notes for ESCU " + latest_tag)

        if latest_branch:
            print(f"Generating release notes       - \033[92m{latest_branch}\033[0m")
            print(f"Compared against               - \033[92m{compare_against}\033[0m")
            print("\n## Release notes for ESCU " + latest_branch)

        print("\n### New Analytics Story")
        self.create_notes(repo_path, stories_added)
        print("\n### Updated Analytics Story")
        self.create_notes(repo_path,stories_modified)
        print("\n### New Analytics")
        self.create_notes(repo_path,detections_added)
        print("\n### Updated Analytics")    
        self.create_notes(repo_path,detections_modified)
        print("\n### Macros Added")    
        self.create_notes(repo_path,macros_added)
        print("\n### Macros Updated")    
        self.create_notes(repo_path,macros_modified)
        print("\n### Lookups Added")    
        self.create_notes(repo_path,lookups_added)
        print("\n### Lookups Updated")    
        self.create_notes(repo_path,lookups_modified)
        print("\n### Playbooks Added")    
        self.create_notes(repo_path,playbooks_added)
        print("\n### Playbooks Updated")    
        self.create_notes(repo_path,playbooks_modified)

        print("\n### Other Updates\n-\n") 
        
        print(f"Release notes completed succesfully")