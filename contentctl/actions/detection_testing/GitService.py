import logging
import os
import pathlib
import git






from contentctl.objects.enums import DetectionTestingMode, DetectionStatus, AnalyticsType


from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    
from contentctl.objects.story import Story
from contentctl.objects.baseline import Baseline
from contentctl.objects.investigation import Investigation
from contentctl.objects.playbook import Playbook
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.detection import Detection
from contentctl.objects.config import test
# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


SSA_PREFIX = "ssa___"
from contentctl.input.director import DirectorOutputDto

from enum import StrEnum, auto
import pygit2
from pygit2.enums import DeltaStatus
from typing import List
class Mode(StrEnum):
    all = auto()
    changes = auto()
    selected = auto()

class simpleGit:
    def __init__(self, director:DirectorOutputDto, config:test):
        self.director = director
        self.config = config
        self.repo = pygit2.Repository(path=str(self.config.path))

    def getContent(self, mode:Mode)->List[Detection]:
        if mode == Mode.all:
            return self.getAll()
        elif mode == Mode.selected:
            return self.getSelected()
        elif mode == Mode.changes:
            return self.getChanges()
        else:
            raise Exception(f"Unsupported Mode '{mode}'")

    def getChanges(self,target_branch:str)->List[Detection]:
        #diffs = self.repo.diff("updates_for_pydantic2","removeTest", context_lines=0, interhunk_lines=0)
        try:
            target_tree = self.repo.revparse_single(target_branch).tree
            diffs = self.repo.index.diff_to_tree(target_tree)
        except Exception as e:
            raise Exception(f"Error parsing diff target_branch '{target_branch}'. Are you certain that it exists?")
        
        #Get the uncommitted changes in the current directory
        diffs2 = self.repo.index.diff_to_workdir()
        
        #Combine the uncommitted changes with the committed changes
        all_diffs = list(diffs) + list(diffs2)

        #Make a filename to content map
        filepath_to_content_map = { obj.file_path:obj for (_,obj) in self.director.name_to_content_map.items()} 
        updated_detections:List[Detection] = []
        updated_macros:List[Macro] = []
        updated_lookups:List[Lookup] =[]

        for diff in all_diffs:
            if type(diff) == pygit2.Patch:
                if diff.delta.status in (DeltaStatus.ADDED, DeltaStatus.MODIFIED, DeltaStatus.RENAMED):
                    print(f"{diff.delta.new_file.raw_path}:{DeltaStatus(diff.delta.status).name}")
                    decoded_path = pathlib.Path(diff.delta.new_file.raw_path.decode('utf-8'))
                    if 'detections/' in str(decoded_path) and decoded_path.suffix == ".yml":
                        detectionObject = filepath_to_content_map.get(decoded_path, None)
                        if isinstance(detectionObject, Detection):
                            updated_detections.append(detectionObject)
                        else:
                            raise Exception(f"Error getting detection object for file {str(decoded_path)}")
                        
                    elif 'macros/' in str(decoded_path) and decoded_path.suffix == ".yml":
                        macroObject = filepath_to_content_map.get(decoded_path, None)
                        if isinstance(macroObject, Macro):
                            updated_macros.append(macroObject)
                        else:
                            raise Exception(f"Error getting macro object for file {str(decoded_path)}")

                    elif 'lookups/' in str(decoded_path):
                        # We need to convert this to a yml. This means we will catch
                        # both changes to a csv AND changes to the YML that uses it
                        decoded_path = decoded_path.with_suffix(".yml")    
                        lookupObject = filepath_to_content_map.get(decoded_path, None)
                        if isinstance(lookupObject, Lookup):
                            # If the CSV and YML were changed, it is possible that 
                            # both could be added to the list. Only add it once
                            if lookupObject not in updated_lookups:
                                updated_lookups.append(lookupObject)
                        else:
                            raise Exception(f"Error getting lookup object for file {str(decoded_path)}")

                    else:
                        print(f"Ignore changes to file {decoded_path} since it is not a detection, macro, or lookup.")
                
                # else:
                #     print(f"{diff.delta.new_file.raw_path}:{DeltaStatus(diff.delta.status).name} (IGNORED)")
                #     pass
            else:
                raise Exception(f"Unrecognized type {type(diff)}")


        # If a detection has at least one dependency on changed content,
        # then we must test it again
        changed_macros_and_lookups = updated_macros + updated_lookups
        
        for detection in self.director.detections:
            if detection in updated_detections:
                # we are already planning to test it, don't need 
                # to add it again
                continue

            for obj in changed_macros_and_lookups:
                if obj in detection.get_content_dependencies():
                   updated_detections.append(detection)
                   break
        
        print([d.name for d in updated_detections])
        return updated_detections


            

    def getAll(self)->List[Detection]:
        return self.director.detections
        
    def getSelected(self)->List[Detection]:
        raise Exception("Not implemented")
        pass

