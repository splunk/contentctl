from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, List, Optional, Union

from pydantic import (
    UUID4,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationInfo,
    computed_field,
    field_validator,
    model_serializer,
    model_validator,
)

from contentctl.objects.story import Story
from contentctl.objects.throttling import Throttling

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from contentctl.objects.annotated_types import CVE_TYPE, MITRE_ATTACK_ID_TYPE
from contentctl.objects.atomic import AtomicEnrichment, AtomicTest
from contentctl.objects.constants import ATTACK_TACTICS_KILLCHAIN_MAPPING
from contentctl.objects.enums import (
    AssetType,
    Cis18Value,
    KillChainPhase,
    NistCategory,
    SecurityContentProductName,
    SecurityDomain,
)
from contentctl.objects.mitre_attack_enrichment import (
    MitreAttackEnrichment,
    MitreAttackGroup,
)


class DetectionTags(BaseModel):
    # detection spec

    model_config = ConfigDict(validate_default=False, extra="forbid")
    analytic_story: list[Story] = Field(...)
    asset_type: AssetType = Field(...)
    group: list[str] = []

    mitre_attack_id: list[MITRE_ATTACK_ID_TYPE] = []
    nist: list[NistCategory] = []

    product: list[SecurityContentProductName] = Field(..., min_length=1)
    throttling: Optional[Throttling] = None
    security_domain: SecurityDomain = Field(...)
    cve: List[CVE_TYPE] = []
    atomic_guid: List[AtomicTest] = []

    # enrichment
    mitre_attack_enrichments: List[MitreAttackEnrichment] = Field(
        [], validate_default=True
    )

    @computed_field
    @property
    def kill_chain_phases(self) -> list[KillChainPhase]:
        phases: set[KillChainPhase] = set()
        for enrichment in self.mitre_attack_enrichments:
            for tactic in enrichment.mitre_attack_tactics:
                phase = KillChainPhase(ATTACK_TACTICS_KILLCHAIN_MAPPING[tactic])
                phases.add(phase)
        return sorted(list(phases))

    # We do not want this to be included in serialization. By default, @property
    # objects are not included in dumps
    @property
    def unique_mitre_attack_groups(self) -> list[MitreAttackGroup]:
        group_set: set[MitreAttackGroup] = set()
        for enrichment in self.mitre_attack_enrichments:
            group_set.update(set(enrichment.mitre_attack_group_objects))
        return sorted(group_set, key=lambda k: k.group)

    # enum is intentionally Cis18 even though field is named cis20 for legacy reasons
    @computed_field
    @property
    def cis20(self) -> list[Cis18Value]:
        if self.security_domain == SecurityDomain.NETWORK:
            return [Cis18Value.CIS_13]
        else:
            return [Cis18Value.CIS_10]

    research_site_url: Optional[HttpUrl] = None
    event_schema: str = "ocsf"
    # TODO (#221): mappings should be fleshed out into a proper class
    mappings: Optional[List] = None
    # annotations: Optional[dict] = None

    # TODO (#268): Validate manual_test has length > 0 if not None
    manual_test: Optional[str] = None

    @model_serializer
    def serialize_model(self):
        # Since this field has no parent, there is no need to call super() serialization function
        return {
            "analytic_story": [story.name for story in self.analytic_story],
            "asset_type": self.asset_type,
            "cis20": self.cis20,
            "kill_chain_phases": self.kill_chain_phases,
            "nist": self.nist,
            "security_domain": self.security_domain,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_attack_enrichments": self.mitre_attack_enrichments,
        }

    @model_validator(mode="after")
    def addAttackEnrichment(self, info: ValidationInfo):
        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        if len(self.mitre_attack_enrichments) > 0:
            raise ValueError(
                "Error, field 'mitre_attack_enrichment' should be empty and dynamically populated"
                f" at runtime. Instead, this field contained: {self.mitre_attack_enrichments}"
            )

        output_dto: Union[DirectorOutputDto, None] = info.context.get(
            "output_dto", None
        )
        if output_dto is None:
            raise ValueError(
                "Context not provided to detection.detection_tags model post validator"
            )

        if output_dto.attack_enrichment.use_enrichment is False:
            return self

        mitre_enrichments: list[MitreAttackEnrichment] = []
        missing_tactics: list[str] = []
        for mitre_attack_id in self.mitre_attack_id:
            try:
                mitre_enrichments.append(
                    output_dto.attack_enrichment.getEnrichmentByMitreID(mitre_attack_id)
                )
            except Exception:
                missing_tactics.append(mitre_attack_id)

        if len(missing_tactics) > 0:
            raise ValueError(f"Missing Mitre Attack IDs. {missing_tactics} not found.")

        self.mitre_attack_enrichments = mitre_enrichments

        return self

    """
    @field_validator('mitre_attack_enrichments', mode="before")
    @classmethod
    def addAttackEnrichments(cls, v:list[MitreAttackEnrichment], info:ValidationInfo)->list[MitreAttackEnrichment]:
        if len(v) > 0:
            raise ValueError(
                f"Error, field 'mitre_attack_enrichment' should be empty and dynamically populated"
                f" at runtime. Instead, this field contained: {str(v)}"
            )


        output_dto:Union[DirectorOutputDto,None]= info.context.get("output_dto",None)
        if output_dto is None:
            raise ValueError("Context not provided to detection.detection_tags.mitre_attack_enrichments")

        enrichments = []

        return enrichments
    """

    @field_validator("mitre_attack_id", mode="after")
    @classmethod
    def sameTypeAndSubtypeNotPresent(
        cls, techniques_and_subtechniques: list[MITRE_ATTACK_ID_TYPE]
    ) -> list[MITRE_ATTACK_ID_TYPE]:
        techniques: list[str] = [
            f"{unknown_technique}."
            for unknown_technique in techniques_and_subtechniques
            if "." not in unknown_technique
        ]
        subtechniques: list[MITRE_ATTACK_ID_TYPE] = [
            unknown_technique
            for unknown_technique in techniques_and_subtechniques
            if "." in unknown_technique
        ]
        subtype_and_parent_exist_exceptions: list[ValueError] = []

        for subtechnique in subtechniques:
            for technique in techniques:
                if subtechnique.startswith(technique):
                    subtype_and_parent_exist_exceptions.append(
                        ValueError(
                            f"    Technique   : {technique.split('.')[0]}\n"
                            f"    SubTechnique: {subtechnique}\n"
                        )
                    )

        if len(subtype_and_parent_exist_exceptions):
            error_string = "\n".join(
                str(e) for e in subtype_and_parent_exist_exceptions
            )
            raise ValueError(
                "Overlapping MITRE Attack ID Techniques and Subtechniques may not be defined. "
                f"Remove the Technique and keep the Subtechnique:\n{error_string}"
            )

        return techniques_and_subtechniques

    @field_validator("analytic_story", mode="before")
    @classmethod
    def mapStoryNamesToStoryObjects(
        cls, v: list[str], info: ValidationInfo
    ) -> list[Story]:
        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        return Story.mapNamesToSecurityContentObjects(
            v, info.context.get("output_dto", None)
        )

    def getAtomicGuidStringArray(self) -> List[str]:
        return [
            str(atomic_guid.auto_generated_guid) for atomic_guid in self.atomic_guid
        ]

    @field_validator("atomic_guid", mode="before")
    @classmethod
    def mapAtomicGuidsToAtomicTests(
        cls, v: List[UUID4], info: ValidationInfo
    ) -> List[AtomicTest]:
        if len(v) == 0:
            return []

        if info.context is None:
            raise ValueError("ValidationInfo.context unexpectedly null")

        output_dto: Union[DirectorOutputDto, None] = info.context.get(
            "output_dto", None
        )
        if output_dto is None:
            raise ValueError(
                "Context not provided to detection.detection_tags.atomic_guid validator"
            )

        atomic_enrichment: AtomicEnrichment = output_dto.atomic_enrichment

        matched_tests: List[AtomicTest] = []
        missing_tests: List[UUID4] = []
        badly_formatted_guids: List[str] = []
        for atomic_guid_str in v:
            try:
                # Ensure that this is a valid UUID
                atomic_guid = uuid.UUID(str(atomic_guid_str))
            except Exception:
                # We will not try to load a test for this since it was invalid
                badly_formatted_guids.append(str(atomic_guid_str))
                continue
            try:
                matched_tests.append(atomic_enrichment.getAtomic(atomic_guid))
            except Exception:
                missing_tests.append(atomic_guid)

        if len(missing_tests) > 0:
            missing_tests_string = (
                f"\n\tWARNING: Failed to find [{len(missing_tests)}] Atomic Test(s) with the "
                "following atomic_guids (called auto_generated_guid in the ART Repo)."
                f"\n\tPlease review the output above for potential exception(s) when parsing the "
                "Atomic Red Team Repo."
                "\n\tVerify that these auto_generated_guid exist and try updating/pulling the "
                f"repo again: {[str(guid) for guid in missing_tests]}"
            )
        else:
            missing_tests_string = ""

        if len(badly_formatted_guids) > 0:
            bad_guids_string = (
                f"The following [{len(badly_formatted_guids)}] value(s) are not properly "
                f"formatted UUIDs: {badly_formatted_guids}\n"
            )
            raise ValueError(f"{bad_guids_string}{missing_tests_string}")

        elif len(missing_tests) > 0:
            raise ValueError(missing_tests_string)

        return matched_tests + [
            AtomicTest.AtomicTestWhenTestIsMissing(test) for test in missing_tests
        ]
        return matched_tests + [
            AtomicTest.AtomicTestWhenTestIsMissing(test) for test in missing_tests
        ]
