import sys

from dataclasses import dataclass

from pydantic import ValidationError
from typing import Union

from splunk_contentctl.objects.enums import SecurityContentProduct
from splunk_contentctl.input.director import Director, DirectorInputDto, DirectorOutputDto


@dataclass(frozen=True)
class ValidateInputDto:
    director_input_dto: DirectorInputDto
    product: SecurityContentProduct


class Validate:

    def execute(self, input_dto: ValidateInputDto) -> None:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)      

        # uuid validation all objects
        try:
            security_content_objects = director_output_dto.detections + director_output_dto.stories + director_output_dto.baselines + director_output_dto.investigations + director_output_dto.playbooks + director_output_dto.deployments
            self.validate_duplicate_uuids(security_content_objects)

            # validate tests
            self.validate_detection_exist_for_test(director_output_dto.tests, director_output_dto.detections)

        except ValueError as e:
            print(e)
            sys.exit(1)
        
        print('Validation of security content successful.')



    def validate_duplicate_uuids(self, security_content_objects):
        duplicate_uuids = list()
        set_objects = set()
        for elem in security_content_objects:
            if elem.id in set_objects:
                duplicate_uuids.append(elem)
            else:
                set_objects.add(elem.id)
    
        if len(duplicate_uuids):
            raise ValueError('ERROR: Duplicate ID found in objects:\n' + '\n'.join([obj.name for obj in duplicate_uuids]))


    def validate_detection_exist_for_test(self, tests : list, detections: list):
        for test in tests:
            found_detection = False
            for detection in detections:
                if test.tests[0].file in detection.file_path:
                     found_detection = True

            if not found_detection:
                raise ValueError("ERROR: detection doesn't exist for test file: " + test.name)

