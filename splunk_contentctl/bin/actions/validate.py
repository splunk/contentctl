

from dataclasses import dataclass

from pydantic import ValidationError
from typing import Union

from bin.objects.enums import SecurityContentProduct
from bin.input.director import Director, DirectorInputDto, DirectorOutputDto


@dataclass(frozen=True)
class ValidateInputDto:
    director_input_dto: DirectorInputDto
    product: SecurityContentProduct


class Validate:

    def execute(self, input_dto: ValidateInputDto) -> None:
        if input_dto.product == SecurityContentProduct.SPLUNK_ENTERPRISE_APP:
            director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
            director = Director(director_output_dto)
            director.execute(input_dto.director_input_dto)

        # elif input_dto.product == SecurityContentProduct.SSA:
        #     factory_output_dto = BAFactoryOutputDto([],[])
        #     factory = BAFactory(factory_output_dto)
        #     factory.execute(input_dto.ba_factory_input_dto)        


        # validate detections

        # uuid validation

        # validate tests
        self.validate_detection_exist_for_test(director_output_dto.tests, director_output_dto.detections)
        
        print('Validation of security content successful.')
        

    def validate_detection_exist_for_test(self, tests : list, detections: list):
        for test in tests:
            found_detection = False
            for detection in detections:
                if test.tests[0].file in detection.file_path:
                     found_detection = True

            if not found_detection:
                ValueError("detection doesn't exist for test file: " + test.name)