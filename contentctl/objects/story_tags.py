

from pydantic import BaseModel, validator, ValidationError
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.enums import StoryCategory

class StoryTags(BaseModel):
    # story spec
    name: str
    analytic_story: str
    category: list[StoryCategory]
    product: list
    usecase: str

    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    mitre_attack_tactics: list = []
    datamodels: list = []
    kill_chain_phases: list = []


    @validator('product')
    def tags_product(cls, v, values):
        valid_products = [
            "Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud",
            "Splunk Security Analytics for AWS", "Splunk Behavioral Analytics"
        ]

        for value in v:
            if value not in valid_products:
                raise ValueError('product is not valid for ' + values['name'] + '. valid products are ' + str(valid_products))
        return v

    @validator('category')
    def category_validate(cls,v,values):
        if len(v) == 0:
            raise ValueError(f"Error for Story '{values['name']}' - at least one 'category' MUST be provided.")
        return v