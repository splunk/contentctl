from __future__ import annotations
from pycvesearch import CVESearch
import functools
import os
import shelve
import time
from typing import Annotated, Any, Union, TYPE_CHECKING
from pydantic import BaseModel,Field
from decimal import Decimal
from requests.exceptions import ReadTimeout

if TYPE_CHECKING:
    from contentctl.objects.config import validate



CVESSEARCH_API_URL = 'https://cve.circl.lu'


class CveEnrichmentObj(BaseModel):
    id:Annotated[str, "^CVE-[1|2][0-9]{3}-[0-9]+$"]
    cvss:Annotated[Decimal, Field(ge=.1, le=10, decimal_places=1)]
    summary:str


    @staticmethod
    def buildEnrichmentOnFailure(id:Annotated[str, "^CVE-[1|2][0-9]{3}-[0-9]+$"], errorMessage:str, 
                                 raise_exception_on_failure:bool=True)->CveEnrichmentObj:
        if raise_exception_on_failure:
            raise Exception(errorMessage)
        message = f"{errorMessage}. Default CVSS of 5.0 used"
        print(message)
        return CveEnrichmentObj(id=id, cvss=Decimal(5.0), summary=message)


# We need a MUCH better way to handle issues with the cve.circl.lu API.
# It is often extremely slow or down, which means that we cannot enrich CVEs.
# Downloading the entire database is VERY large, but I don't know that there
# is an alternative.
# Being able to include CVEs that have not made it into this database, or additonal
# enriching comments on pre-existing CVEs, would also be extremely useful.
timeout_error = False
class CveEnrichment(BaseModel):
    use_enrichment: bool = True
    cve_api_obj: Union[CVESearch,None] = None
    

    class Config:
        # Arbitrary_types are allowed to let us use the CVESearch Object
        arbitrary_types_allowed = True
        frozen = True
        

    @staticmethod
    def getCveEnrichment(config:validate, timeout_seconds:int=10)->CveEnrichment:

        if config.enrichments:
            try:
                cve_api_obj = CVESearch(CVESSEARCH_API_URL, timeout=timeout_seconds)
                return CveEnrichment(use_enrichment=True, cve_api_obj=cve_api_obj)
            except Exception as e:
                raise Exception(f"Error setting CVE_SEARCH API to: {CVESSEARCH_API_URL}: {str(e)}")
        
        return CveEnrichment(use_enrichment=False, cve_api_obj=None)


    @functools.cache
    def enrich_cve(self, cve_id:str, raise_exception_on_failure:bool=True)->Union[CveEnrichmentObj,None]:
        global timeout_error

        if not self.use_enrichment:
            return None
        
        if timeout_error:
            message = f"Previous timeout during enrichment - CVE {cve_id} enrichment skipped."
            return CveEnrichmentObj.buildEnrichmentOnFailure(id = cve_id, errorMessage=f"WARNING, {message}", 
                                                             raise_exception_on_failure=raise_exception_on_failure) 
 
        cve_enriched:dict[str,Any] = dict()

        try:
            result = self.cve_api_obj.id(cve_id)
            cve_enriched['id'] = cve_id
            cve_enriched['cvss'] = result['cvss']
            cve_enriched['summary'] = result['summary']
            return CveEnrichmentObj.model_validate(cve_enriched)
        except ReadTimeout as e:
            message = f"Timeout enriching CVE {cve_id}: {str(e)} after {self.cve_api_obj.timeout} seconds."\
                      f" All other CVE Enrichment has been disabled"
            #Set a global value to true so future runs don't waste time on this
            timeout_error = True
            return CveEnrichmentObj.buildEnrichmentOnFailure(id = cve_id, errorMessage=f"ERROR, {message}", 
                                                             raise_exception_on_failure=raise_exception_on_failure)
        except Exception as e:
            message = f"Error enriching CVE {cve_id}. Are you positive this CVE exists: {str(e)}"
            return CveEnrichmentObj.buildEnrichmentOnFailure(id = cve_id, errorMessage=f"WARNING, {message}", 
                                                             raise_exception_on_failure=raise_exception_on_failure)
