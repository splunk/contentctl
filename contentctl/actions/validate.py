import sys

from dataclasses import dataclass

from pydantic import ValidationError
from typing import Union

from contentctl.objects.enums import SecurityContentProduct
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    SecurityContentObject_Abstract,
)
from contentctl.input.director import Director, DirectorOutputDto

from contentctl.objects.config import validate
from contentctl.enrichments.attack_enrichment import AttackEnrichment
from contentctl.enrichments.cve_enrichment import CveEnrichment
from contentctl.objects.atomic import AtomicTest


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
            [],
        )

        director = Director(director_output_dto)
        director.execute(input_dto)
        return director_output_dto

    def validate_duplicate_uuids(
        self, security_content_objects: list[SecurityContentObject_Abstract]
    ):
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
        duplicate_messages = []
        for uuid in duplicate_uuids:
            duplicate_uuid_content = [
                str(content.file_path)
                for content in security_content_objects
                if content.id in duplicate_uuids
            ]
            duplicate_messages.append(
                f"Duplicate UUID [{uuid}] in {duplicate_uuid_content}"
            )

        raise ValueError(
            "ERROR: Duplicate ID(s) found in objects:\n"
            + "\n - ".join(duplicate_messages)
        )
