
class ContentFields():

    @classmethod
    def get_content_fields(self) -> list:
        select = {
            'name': "",
            'id': "",
            'version': "",
            'date': "", 
            'author': "",
            'status': "", 
            'type': "", 
            'description': "", 
            'data_source': "",
            'search': "", 
            'how_to_implement': "", 
            'known_false_positives': "", 
            'references': "",
            'tags': {
                'analytic_story': "",
                'asset_type': "",
                'confidence': "", 
                'impact': "", 
                'message': "", 
                'mitre_attack_id': "",
                'observable': [{
                    'name': "",
                    'type': "", 
                    'role': "",
                }],
                'product': "",
                'required_fields': "",
                'risk_score': "",
                'security_domain': "", 
        },
            'tests':[{
                'name': "", 
                'attack_data':[{
                    'data': "",
                    'source': "",
                    'sourcetype': "", 
                }]
            }]
        }
        return select