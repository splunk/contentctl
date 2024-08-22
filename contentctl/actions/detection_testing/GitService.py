import logging
import os
import pathlib
import pygit2
from pygit2.enums import DeltaStatus
from typing import List, Optional
from pydantic import BaseModel, FilePath
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    

from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.detection import Detection
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.config import test_common, All, Changes, Selected

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)



from contentctl.input.director import DirectorOutputDto



class GitService(BaseModel):
    director: DirectorOutputDto
    config: test_common
    gitHash: Optional[str] = None
    
    def getHash(self)->str:
        if self.gitHash is None:
            raise Exception("Cannot get hash of repo, it was not set")
        return self.gitHash


    def getContent(self)->List[Detection]:
        if isinstance(self.config.mode, Selected):
            return self.getSelected(self.config.mode.files)
        elif isinstance(self.config.mode, Changes):
            return self.getChanges(self.config.mode.target_branch)
        if isinstance(self.config.mode, All):
            return self.getAll()
        else:
            raise Exception(f"Could not get content to test. Unsupported test mode '{self.config.mode}'")
    def getAll(self)->List[Detection]:
        return self.director.detections
    
    def getChanges(self, target_branch:str)->List[Detection]:
        repo = pygit2.Repository(path=str(self.config.path))

        try:
            target_tree = repo.revparse_single(target_branch).tree
            self.gitHash = target_tree.id
            diffs = repo.index.diff_to_tree(target_tree)
        except Exception as e:
            raise Exception(f"Error parsing diff target_branch '{target_branch}'. Are you certain that it exists?")
        
        #Get the uncommitted changes in the current directory
        diffs2 = repo.index.diff_to_workdir()
        
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
                    #print(f"{DeltaStatus(diff.delta.status).name:<8}:{diff.delta.new_file.raw_path}")
                    decoded_path = pathlib.Path(diff.delta.new_file.raw_path.decode('utf-8'))
                    # Note that we only handle updates to detections, lookups, and macros at this time. All other changes are ignored.
                    if decoded_path.is_relative_to(self.config.path/"detections") and decoded_path.suffix == ".yml":
                        detectionObject = filepath_to_content_map.get(decoded_path, None)
                        if isinstance(detectionObject, Detection):
                            updated_detections.append(detectionObject)
                        else:
                            raise Exception(f"Error getting detection object for file {str(decoded_path)}")
                        
                    elif decoded_path.is_relative_to(self.config.path/"macros") and decoded_path.suffix == ".yml":
                        macroObject = filepath_to_content_map.get(decoded_path, None)
                        if isinstance(macroObject, Macro):
                            updated_macros.append(macroObject)
                        else:
                            raise Exception(f"Error getting macro object for file {str(decoded_path)}")

                    elif decoded_path.is_relative_to(self.config.path/"lookups"):
                        # We need to convert this to a yml. This means we will catch
                        # both changes to a csv AND changes to the YML that uses it
                        if decoded_path.suffix == ".yml":
                            updatedLookup = filepath_to_content_map.get(decoded_path, None)
                            if not isinstance(updatedLookup,Lookup):
                                raise Exception(f"Expected {decoded_path} to be type {type(Lookup)}, but instead if was {(type(updatedLookup))}")
                            updated_lookups.append(updatedLookup)

                        elif decoded_path.suffix == ".csv":
                            # If the CSV was updated, we want to make sure that we 
                            # add the correct corresponding Lookup object.
                            #Filter to find the Lookup Object the references this CSV
                            matched = list(filter(lambda x: x.filename is not None and x.filename == decoded_path, self.director.lookups))
                            if len(matched) == 0:
                                raise Exception(f"Failed to find any lookups that reference the modified CSV file  '{decoded_path}'")
                            elif len(matched) > 1:
                                raise Exception(f"More than 1 Lookup reference the modified CSV file '{decoded_path}': {[l.file_path for l in matched ]}")
                            else:
                                updatedLookup = matched[0]
                        elif decoded_path.suffix == ".mlmodel":
                            # Detected a changed .mlmodel file. However, since we do not have testing for these detections at 
                            # this time, we will ignore this change.
                            updatedLookup = None
                            

                        else:
                            raise Exception(f"Detected a changed file in the lookups/ directory '{str(decoded_path)}'.\n"
                                            "Only files ending in .csv, .yml, or .mlmodel are supported in this "
                                            "directory. This file must be removed from the lookups/ directory.")
                        
                        if updatedLookup is not None and updatedLookup not in updated_lookups:
                            # It is possible that both the CSV and YML have been modified for the same lookup,
                            # and we do not want to add it twice. 
                            updated_lookups.append(updatedLookup)

                    else:
                        pass
                        #print(f"Ignore changes to file {decoded_path} since it is not a detection, macro, or lookup.")
            else:
                raise Exception(f"Unrecognized diff type {type(diff)}")


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

        #Print out the names of all modified/new content
        modifiedAndNewContentString = "\n - ".join(sorted([d.name for d in updated_detections]))

        print(f"[{len(updated_detections)}] Pieces of modifed and new content (this may include experimental/deprecated/manual_test content):\n - {modifiedAndNewContentString}")
        return updated_detections

    def getSelected(self, detectionFilenames: List[FilePath]) -> List[Detection]:
        filepath_to_content_map: dict[FilePath, SecurityContentObject] = {
        obj.file_path: obj for (_, obj) in self.director.name_to_content_map.items() if obj.file_path is not None
    }
        errors = []
        detections: List[Detection] = []
        for name in detectionFilenames:
            obj = filepath_to_content_map.get(name, None)
            if obj is None:
                errors.append(f"There is no detection file or security_content_object at '{name}'")
            elif not isinstance(obj, Detection):
                errors.append(f"The security_content_object at '{name}' is of type '{type(obj).__name__}', NOT '{Detection.__name__}'")
            else:
                detections.append(obj)

        if errors:
            errorsString = "\n - ".join(errors)
            raise Exception(f"The following errors were encountered while getting selected detections to test:\n - {errorsString}")
        return detections