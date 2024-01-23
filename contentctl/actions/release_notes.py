import os

from dataclasses import dataclass

from contentctl.input.director import DirectorInputDto, Director, DirectorOutputDto
from contentctl.output.svg_output import SvgOutput
from contentctl.output.attack_nav_output import AttackNavOutput
from git import Repo
import re
import yaml


@dataclass(frozen=True)
class ReleaseNotesInputDto:
    director_input_dto: DirectorInputDto

class ReleaseNotes:
    def release_notes(self, input_dto: DirectorInputDto, tag) -> None:

        def create_notes(file_paths):

            # repo_path = '/Users/bpatel/Research/malware/gitlab/security_content_gitlab/'
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
                                if 'name' in data and'stories/' in file_path:
                                    story_link = "https://research.splunk.com/" + file_path.replace(repo_path,"")
                                    print("- "+"["+f"{data['name']}"+"]"+"("+story_link+")")
                                # Check and create detection link
                                if 'name' in data and 'id' in data and 'detections/' in file_path:
                                    temp_link = "https://research.splunk.com/" + file_path.replace(repo_path,"")
                                    pattern = r'(?<=/)[^/]*$'
                                    detection_link = re.sub(pattern, data['id'], temp_link)
                                    detection_link = detection_link.replace("detections/","" )

                                    print("- "+"["+f"{data['name']}"+"]"+"("+detection_link+")")               
                            except yaml.YAMLError as exc:
                                print(f"Error parsing YAML file {file_path}: {exc}")
                else:
                    print(f"File not found or is not a file: {file_path}")

        # print(tag)
        # print(input_dto)
        # #print(input_dto.path)

              ### Remove hard coded path
        print("Generating Release Notes - Compared with previous tag")
        repo_path = '/Users/bpatel/Research/malware/gitlab/security_content_gitlab/'
        directories = ['detections/','stories/']
        repo = Repo(repo_path)
        latest_tag=tag
        previous_tag= new_version = ".".join([latest_tag.split('.')[0], str(int(latest_tag.split('.')[1]) - 1), latest_tag.split('.')[2]]) if latest_tag else latest_tag
        if latest_tag not in repo.tags or previous_tag not in repo.tags:
            raise ValueError("One of the tags does not exist in the repository.")
        commit1 = repo.commit(latest_tag)
        commit2 = repo.commit(previous_tag)
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
        detections_modified = []
        detections_added = []
        stories_added = []
        stories_modified = []

        for file in modified_files:
            file=repo_path+file
            if 'detections/' in file:
                detections_modified.append(file)
            if 'stories/' in file:
                stories_modified.append(file)

        for file in added_files:
            file=repo_path+file
            if 'detections/' in file:
                detections_added.append(file)
            if 'stories/' in file:
                stories_added.append(file)


        release_notes = ReleaseNotes()
        print("\n## Release notes for ESCU" + latest_tag + "##")

        print("\n### New Analytics Story###")
        create_notes(stories_added)
        print("\n### Updated Analytics Story###")
        create_notes(stories_modified)
        print("\n### New Analytics###")
        create_notes(detections_added)
        print("\n### Updated Analytics###")    
        create_notes(detections_modified)
        print("\n### Other Updates###") 

        # director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        # director = Director(director_output_dto)
        # director.execute(input_dto.director_input_dto)

        # svg_output = SvgOutput()
        # svg_output.writeObjects(
        #     director_output_dto.detections, 
        #     os.path.join(input_dto.director_input_dto.input_path, "reporting")
        # )
        
        # attack_nav_output = AttackNavOutput()        
        # attack_nav_output.writeObjects(
        #     director_output_dto.detections, 
        #     os.path.join(input_dto.director_input_dto.input_path, "reporting")
        # )
        
        print('Actions called succesfully!')