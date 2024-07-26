
import pathlib
from contentctl.input.director import Director, DirectorOutputDto
from contentctl.objects.config import validate
from contentctl.enrichments.attack_enrichment import AttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.objects.atomic import AtomicTest
from contentctl.helper.utils import Utils


class Validate:
    def execute(self, input_dto: validate) -> DirectorOutputDto:

        director_output_dto = DirectorOutputDto(
            AtomicTest.getAtomicTestsFromArtRepo(
                repo_path=input_dto.getAtomicRedTeamRepoPath(),
                enabled=input_dto.enrichments,
            ),
            AttackEnrichment.getAttackEnrichment(input_dto),
            CveEnrichment.getCveEnrichment(input_dto),
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
        )

        director = Director(director_output_dto)
        director.execute(input_dto)
        self.ensure_no_orphaned_files_in_lookups(input_dto.path, director_output_dto)
        return director_output_dto

    
    def ensure_no_orphaned_files_in_lookups(self, repo_path:pathlib.Path, director_output_dto:DirectorOutputDto):
        """
        This function ensures that only files which are relevant to lookups are included in the lookups folder.
        This means that a file must be either:
        1. A lookup YML (.yml)
        2. A lookup CSV (.csv) which is referenced by a YML
        3. A lookup MLMODEL (.mlmodel) which is referenced by a YML.
        
        All other files, includes CSV and MLMODEL files which are NOT
        referenced by a YML, will generate an exception from this function.
        
        Args:
            repo_path (pathlib.Path): path to the root of the app
            director_output_dto (DirectorOutputDto): director object with all constructed content

        Raises:
            Exception: An Exception will be raised if there are any non .yml, .csv, or .mlmodel 
            files in this directory. Additionally, an exception will be raised if there 
            exists one or more .csv or .mlmodel files that are not referenced by at least 1 
            detection .yml file in this directory. 
            This avoids having additional, unused files in this directory that may be copied into
            the app when it is built (which can cause appinspect errors or larger app size.)
        """        
        lookupsDirectory = repo_path/"lookups"
        
        # Get all of the files referneced by Lookups
        usedLookupFiles:list[pathlib.Path] = [lookup.filename for lookup in director_output_dto.lookups if lookup.filename is not None] + [lookup.file_path for lookup in director_output_dto.lookups if lookup.file_path is not None]

        # Get all of the mlmodel and csv files in the lookups directory
        csvAndMlmodelFiles  = Utils.get_security_content_files_from_directory(lookupsDirectory, allowedFileExtensions=[".yml",".csv",".mlmodel"], fileExtensionsToReturn=[".csv",".mlmodel"])
        
        # Generate an exception of any csv or mlmodel files exist but are not used
        unusedLookupFiles:list[pathlib.Path] = [testFile for testFile in csvAndMlmodelFiles if testFile not in usedLookupFiles]
        if len(unusedLookupFiles) > 0:
            raise Exception(f"The following .csv or .mlmodel files exist in '{lookupsDirectory}', but are not referenced by a lookup file: {[str(path) for path in unusedLookupFiles]}")
        return
    