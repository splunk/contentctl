
import pathlib

from contentctl.input.director import Director, DirectorOutputDto
from contentctl.objects.config import validate
from contentctl.enrichments.attack_enrichment import AttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.objects.atomic import AtomicEnrichment
from contentctl.helper.utils import Utils
from contentctl.objects.data_source import DataSource
from contentctl.helper.splunk_app import SplunkApp


class Validate:
    def execute(self, input_dto: validate) -> DirectorOutputDto:
        director_output_dto = DirectorOutputDto(
            AtomicEnrichment.getAtomicEnrichment(input_dto),
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
            []
        )

        director = Director(director_output_dto)
        director.execute(input_dto)
        self.ensure_no_orphaned_files_in_lookups(input_dto.path, director_output_dto)
        if input_dto.data_source_TA_validation:
            self.validate_latest_TA_information(director_output_dto.data_sources)
            
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
    

    def validate_latest_TA_information(self, data_sources: list[DataSource]) -> None:
        validated_TAs: list[tuple[str, str]] = []
        errors:list[str] = []
        print("----------------------")
        print("Validating latest TA:")
        print("----------------------")
        for data_source in data_sources:
            for supported_TA in data_source.supported_TA:
                ta_identifier = (supported_TA.name, supported_TA.version)
                if ta_identifier in validated_TAs:
                    continue
                if supported_TA.url is not None:
                    validated_TAs.append(ta_identifier)
                    uid = int(str(supported_TA.url).rstrip('/').split("/")[-1])
                    try:
                        splunk_app = SplunkApp(app_uid=uid)
                        if splunk_app.latest_version != supported_TA.version:
                            errors.append(f"Version mismatch in '{data_source.file_path}' supported TA '{supported_TA.name}'"
                                          f"\n  Latest version on Splunkbase    : {splunk_app.latest_version}"
                                          f"\n  Version specified in data source: {supported_TA.version}")
                    except Exception as e:
                        errors.append(f"Error processing checking version of TA {supported_TA.name}: {str(e)}")
                            
        if len(errors) > 0:
            errorString = '\n\n'.join(errors)
            raise Exception(f"[{len(errors)}] or more TA versions are out of date or have other errors."
                            f"Please update the following data sources with the latest versions of "
                            f"their supported tas:\n\n{errorString}")
        print("All TA versions are up to date.")
        


