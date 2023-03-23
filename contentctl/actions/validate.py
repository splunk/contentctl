import sys

from dataclasses import dataclass

from pydantic import ValidationError
from typing import Union

from contentctl.objects.enums import SecurityContentProduct
from contentctl.input.director import (
    Director,
    DirectorInputDto,
    DirectorOutputDto,
)


@dataclass(frozen=True)
class ValidateInputDto:
    director_input_dto: DirectorInputDto


class Validate:
    def execute(self, input_dto: ValidateInputDto) -> None:
        director_output_dto = DirectorOutputDto([], [], [], [], [], [], [], [])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        # uuid validation all objects
        try:
            security_content_objects = (
                director_output_dto.detections
                + director_output_dto.stories
                + director_output_dto.baselines
                + director_output_dto.investigations
                + director_output_dto.playbooks
            )
            self.validate_duplicate_uuids(security_content_objects)

            # validate tests
            self.validate_detection_exist_for_test(
                director_output_dto.tests, director_output_dto.detections
            )

        except ValueError as e:
            print(e)
            sys.exit(1)

        return None

    def validate_duplicate_uuids(self, security_content_objects):
        all_uuids = set()
        duplicate_uuids = set()
        for elem in security_content_objects:
            if elem.id in all_uuids:
                # The uuid has been found more than once
                duplicate_uuids.add(elem.id)
            else:
                # This is the first time the uuid has been found
                all_uuids.add(elem.id)

        if len(duplicate_uuids) == 0:
            return

        # At least once duplicate uuid has been found. Enumerate all
        # the pieces of content that use duplicate uuids
        content_with_duplicate_uuid = [
            content_object
            for content_object in security_content_objects
            if content_object.id in duplicate_uuids
        ]

        raise ValueError(
            "ERROR: Duplicate ID found in objects:\n"
            + "\n".join([obj.name for obj in content_with_duplicate_uuid])
        )

    def validate_detection_exist_for_test(self, tests: list, detections: list):
        for test in tests:
            found_detection = False
            for detection in detections:
                if test.tests[0].file in detection.file_path:
                    found_detection = True

            if not found_detection:
                raise ValueError(
                    "ERROR: detection doesn't exist for test file: " + test.name
                )
