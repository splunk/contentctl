from __future__ import annotations
from pycvesearch import CVESearch
from typing import Annotated, Union, TYPE_CHECKING
from pydantic import ConfigDict, BaseModel, Field, computed_field
from decimal import Decimal
from contentctl.objects.annotated_types import CVE_TYPE

if TYPE_CHECKING:
    from contentctl.objects.config import validate


CVESSEARCH_API_URL = "https://cve.circl.lu"


class CveEnrichmentObj(BaseModel):
    id: CVE_TYPE
    cvss: Annotated[Decimal, Field(ge=0.1, le=10, decimal_places=1)]
    summary: str

    @computed_field
    @property
    def url(self) -> str:
        BASE_NVD_URL = "https://nvd.nist.gov/vuln/detail/"
        return f"{BASE_NVD_URL}{self.id}"


class CveEnrichment(BaseModel):
    use_enrichment: bool = True
    cve_api_obj: Union[CVESearch, None] = None

    # Arbitrary_types are allowed to let us use the CVESearch Object
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    @staticmethod
    def getCveEnrichment(
        config: validate,
        timeout_seconds: int = 10,
        force_disable_enrichment: bool = True,
    ) -> CveEnrichment:
        if force_disable_enrichment:
            return CveEnrichment(use_enrichment=False, cve_api_obj=None)

        if config.enrichments:
            try:
                cve_api_obj = CVESearch(CVESSEARCH_API_URL, timeout=timeout_seconds)
                return CveEnrichment(use_enrichment=True, cve_api_obj=cve_api_obj)
            except Exception as e:
                raise Exception(
                    f"Error setting CVE_SEARCH API to: {CVESSEARCH_API_URL}: {str(e)}"
                )

        return CveEnrichment(use_enrichment=False, cve_api_obj=None)

    def enrich_cve(
        self, cve_id: str, raise_exception_on_failure: bool = True
    ) -> CveEnrichmentObj:
        if not self.use_enrichment:
            return CveEnrichmentObj(
                id=cve_id,
                cvss=Decimal(5.0),
                summary="SUMMARY NOT AVAILABLE! ONLY THE LINK WILL BE USED AT THIS TIME",
            )
        else:
            print("WARNING - Dynamic enrichment not supported at this time.")
            return CveEnrichmentObj(
                id=cve_id,
                cvss=Decimal(5.0),
                summary="SUMMARY NOT AVAILABLE! ONLY THE LINK WILL BE USED AT THIS TIME",
            )
        # Depending on needs, we may add dynamic enrichment functionality back to the tool
