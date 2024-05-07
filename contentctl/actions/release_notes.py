import os
from contentctl.objects.config import release_notes
from git import Repo
import re
import yaml
import pathlib
from typing import List, Union



class ReleaseNotes:
    def create_notes(self,repo_path:pathlib.Path, file_paths:List[pathlib.Path], header:str)->dict[str,Union[List[str], str]]:
        updates:List[str] = []
        warnings:List[str] = []
        for file_path in file_paths:
            # Check if the file exists
            if file_path.exists() and file_path.is_file():
                # Check if the file is a YAML file
                if file_path.suffix in ['.yaml', '.yml']:
                    # Read and parse the YAML file
                    with open(file_path, 'r') as file:
                        try:
                            data = yaml.safe_load(file)
                            # Check and create story link
                            if 'name' in data and 'stories' in file_path.parts:
                                story_link = "https://research.splunk.com/stories/" + data['name']
                                story_link=story_link.replace(" ","_")
                                story_link = story_link.lower()
                                updates.append("- "+"["+f"{data['name']}"+"]"+"("+story_link+")")
            
                            if 'name' in data and'playbooks' in file_path.parts:
                                playbook_link = "https://research.splunk.com/" + str(file_path).replace(str(repo_path),"")
                                playbook_link=playbook_link.replace(".yml","/").lower()
                                updates.append("- "+"["+f"{data['name']}"+"]"+"("+playbook_link+")")

                            if 'name' in data and'macros' in file_path.parts:
                                updates.append("- " + f"{data['name']}")

                            if 'name' in data and'lookups' in file_path.parts:
                                updates.append("- " + f"{data['name']}")

                            # Create only SSA link when its production
                            if 'name' in data and 'id' in data and 'ssa_detections' in file_path.parts:
                                if data['status'] == "production":
                                    temp_link = "https://research.splunk.com/" + str(file_path).replace(str(repo_path),"")
                                    pattern = r'(?<=/)[^/]*$'
                                    detection_link = re.sub(pattern, data['id'], temp_link)
                                    detection_link = detection_link.replace("detections","" )
                                    detection_link = detection_link.replace("ssa_/","" )
                                    updates.append("- "+"["+f"{data['name']}"+"]"+"("+detection_link+")")   

                                if data['status'] == "validation":
                                    updates.append("- "+f"{data['name']}"+" (Validation Mode)")   
                                

                            # Check and create detection link
                            if 'name' in data and 'id' in data and 'detections' in file_path.parts and not 'ssa_detections' in file_path.parts and 'detections/deprecated' not in file_path.parts:
                                
                                if data['status'] == "production":
                                    temp_link = "https://research.splunk.com" + str(file_path).replace(str(repo_path),"")
                                    pattern = r'(?<=/)[^/]*$'
                                    detection_link = re.sub(pattern, data['id'], temp_link)
                                    detection_link = detection_link.replace("detections","" )
                                    detection_link = detection_link.replace(".com//",".com/" )
                                    updates.append("- "+"["+f"{data['name']}"+"]"+"("+detection_link+")") 
                                
                                if data['status'] == "deprecated":
                                    temp_link = "https://research.splunk.com" + str(file_path).replace(str(repo_path),"")
                                    pattern = r'(?<=/)[^/]*$'
                                    detection_link = re.sub(pattern, data['id'], temp_link)
                                    detection_link = detection_link.replace("detections","" )
                                    detection_link = detection_link.replace(".com//",".com/" )
                                    updates.append("- "+"["+f"{data['name']}"+"]"+"("+detection_link+")")
                            
                        except yaml.YAMLError as exc:
                            raise Exception(f"Error parsing YAML file for release_notes {file_path}: {str(exc)}")
            else:
                warnings.append(f"Error parsing YAML file for release_notes. File not found or is not a file: {file_path}")
        #print out all updates at once
        success_header = f'### {header} - [{len(updates)}]'
        warning_header = f'### {header} - [{len(warnings)}]'
        return {'header': success_header, 'changes': sorted(updates), 
                'warning_header': warning_header, 'warnings': warnings}
        

    def release_notes(self, config:release_notes) -> None:

        ### Remove hard coded path
        directories = ['detections/','stories/','macros/','lookups/','playbooks/','ssa_detections/']
        
        repo = Repo(config.path)
        # Ensure the new tag is in the tags if tags are supplied
      
        if config.new_tag:    
            if config.new_tag not in repo.tags:
                raise Exception(f"new_tag {config.new_tag} does not exist in the repository. Make sure your branch nameis ")
            if config.old_tag is None:
                #Old tag was not supplied, so find the index of the new tag, then get the tag before it
                tags_sorted = sorted(repo.tags, key=lambda t: t.commit.committed_datetime, reverse=True)
                tags_names_sorted = [tag.name for tag in tags_sorted]            
                new_tag_index = tags_names_sorted.index(config.new_tag)
                try:
                    config.old_tag = tags_names_sorted[new_tag_index+1]
                except Exception:
                    raise Exception(f"old_tag cannot be inferred.  {config.new_tag} is the oldest tag in the repo!")   
            latest_tag = config.new_tag
            previous_tag = config.old_tag   
            commit1 = repo.commit(latest_tag)
            commit2 = repo.commit(previous_tag)       
            diff_index = commit2.diff(commit1)

        # Ensure the branch is in the repo          
        if config.latest_branch:
            #If a branch name is supplied, compare against develop
            if config.latest_branch not in repo.branches:
                raise ValueError(f"latest branch {config.latest_branch} does not exist in the repository. Make sure your branch name is correct")
            compare_against = "develop"
            commit1 = repo.commit(config.latest_branch)
            commit2 = repo.commit(compare_against)    
            diff_index = commit2.diff(commit1)
        
        modified_files:List[pathlib.Path] = []
        added_files:List[pathlib.Path] = []
        for diff in diff_index:
            file_path = pathlib.Path(diff.a_path)

            # Check if the file is in the specified directories
            if any(str(file_path).startswith(directory) for directory in directories):
                # Check if a file is Modified
                if diff.change_type == 'M':
                    modified_files.append(file_path)


                # Check if a file is Added
                elif diff.change_type == 'A':
                    added_files.append(file_path)
                    # print(added_files)
        detections_added:List[pathlib.Path] = []
        ba_detections_added:List[pathlib.Path] = []
        stories_added:List[pathlib.Path] = []
        macros_added:List[pathlib.Path] = []
        lookups_added:List[pathlib.Path] = []
        playbooks_added:List[pathlib.Path] = []      
        detections_modified:List[pathlib.Path] = []
        ba_detections_modified:List[pathlib.Path] = []
        stories_modified:List[pathlib.Path] = []
        macros_modified:List[pathlib.Path] = []
        lookups_modified:List[pathlib.Path] = []
        playbooks_modified:List[pathlib.Path] = []
        detections_deprecated:List[pathlib.Path] = []

        for file in modified_files:
            file= config.path / file
            if 'detections' in file.parts and 'ssa_detections' not in file.parts and 'deprecated' not in file.parts:
                detections_modified.append(file)
            if 'detections' in file.parts and 'ssa_detections' not in file.parts and 'deprecated' in file.parts:
                detections_deprecated.append(file)
            if 'stories' in file.parts:
                stories_modified.append(file)
            if 'macros' in file.parts:
                macros_modified.append(file)
            if 'lookups' in file.parts:
                lookups_modified.append(file)
            if 'playbooks' in file.parts:
                playbooks_modified.append(file)
            if 'ssa_detections' in file.parts:
                ba_detections_modified.append(file)

        for file in added_files:
            file=config.path / file
            if 'detections' in file.parts and 'ssa_detections' not in file.parts:
                detections_added.append(file)
            if 'stories' in file.parts:
                stories_added.append(file)
            if 'macros' in file.parts:
                macros_added.append(file)
            if 'lookups' in file.parts:
                lookups_added.append(file)
            if 'playbooks' in file.parts:
                playbooks_added.append(file)
            if 'ssa_detections' in file.parts:
                ba_detections_added.append(file)

        if config.new_tag:

            print(f"Generating release notes       - \033[92m{latest_tag}\033[0m")
            print(f"Compared against               - \033[92m{previous_tag}\033[0m")
            print("\n## Release notes for ESCU " + latest_tag)

        if config.latest_branch:
            print(f"Generating release notes       - \033[92m{config.latest_branch}\033[0m")
            print(f"Compared against               - \033[92m{compare_against}\033[0m")
            print("\n## Release notes for ESCU " + config.latest_branch)

        notes = [self.create_notes(config.path, stories_added, header="New Analytic Story"),
                self.create_notes(config.path,stories_modified, header="Updated Analytic Story"),
                self.create_notes(config.path,detections_added, header="New Analytics"),
                self.create_notes(config.path,detections_modified, header="Updated Analytics"),
                self.create_notes(config.path,macros_added, header="Macros Added"),
                self.create_notes(config.path,macros_modified, header="Macros Updated"),
                self.create_notes(config.path,lookups_added, header="Lookups Added"),
                self.create_notes(config.path,lookups_modified, header="Lookups Updated"),
                self.create_notes(config.path,playbooks_added, header="Playbooks Added"),
                self.create_notes(config.path,playbooks_modified, header="Playbooks Updated"),
                self.create_notes(config.path,detections_deprecated, header="Deprecated Analytics")]
        
        #generate and show ba_notes in a different section
        ba_notes = [self.create_notes(config.path,ba_detections_added, header="New BA Analytics"),
                    self.create_notes(config.path,ba_detections_modified, header="Updated BA Analytics") ]
        
        
        def printNotes(notes:List[dict[str,Union[List[str], str]]], outfile:Union[pathlib.Path,None]=None):
            num_changes = sum([len(note['changes']) for note in notes])
            num_warnings = sum([len(note['warnings']) for note in notes])
            lines:List[str] = []
            lines.append(f"Total New and Updated Content: [{num_changes}]")
            for note in notes:
                lines.append("")
                lines.append(note['header'])
                lines+=(note['changes'])
            
            lines.append(f"\n\nTotal Warnings: [{num_warnings}]")
            for note in notes:
                if len(note['warnings']) > 0:
                    lines.append(note['warning_header'])
                    lines+=note['warnings']
            text_blob = '\n'.join(lines)
            print(text_blob)
            if outfile is not None:
                with open(outfile,'w') as writer:
                    writer.write(text_blob)
            
        printNotes(notes, config.releaseNotesFilename(f"release_notes.txt"))

        print("\n\n### Other Updates\n-\n")
        print("\n## BA Release Notes")
        printNotes(ba_notes, config.releaseNotesFilename("ba_release_notes.txt"))
        print(f"Release notes completed succesfully")