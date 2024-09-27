from typing import Any
from contentctl.objects.enums import DataSource


class NewContentQuestions:

    @classmethod
    def get_questions_detection(cls) -> list[dict[str,Any]]:
        questions = [
            {
                "type": "text",
                "message": "enter detection name",
                "name": "detection_name",
                "default": "Powershell Encoded Command",
            },
            {
                'type': 'select',
                'message': 'what kind of detection is this',
                'name': 'detection_kind',
                'choices': [
                    'endpoint',
                    'cloud',
                    'application',
                    'network',
                    'web'
                ],
                'default': 'endpoint'
            },
            {
                'type': 'text',
                'message': 'enter author name',
                'name': 'detection_author',
            },
            {
                "type": "select",
                "message": "select a detection type",
                "name": "detection_type",
                "choices": [
                    "TTP",
                    "Anomaly",
                    "Hunting",
                    "Baseline",
                    "Investigation",
                    "Correlation",
                ],
                "default": "TTP",
            },
            {
                'type': 'checkbox',
                'message': 'Your data source',
                'name': 'data_source',
                #In the future, we should dynamically populate this from the DataSource Objects we have parsed from the data_sources directory
                'choices': sorted(DataSource._value2member_map_ )
                
            },
            {
                "type": "text",
                "message": "enter search (spl)",
                "name": "detection_search",
                "default": "| UPDATE_SPL",
            },
            {
                "type": "text",
                "message": "enter MITRE ATT&CK Technique IDs related to the detection, comma delimited for multiple",
                "name": "mitre_attack_ids",
                "default": "T1003.002",
            },
            {
                'type': 'select',
                'message': 'security_domain for detection',
                'name': 'security_domain',
                'choices': [
                    'access',
                    'endpoint',
                    'network',
                    'threat',
                    'identity',
                    'audit'
                ],
                'default': 'endpoint'
            },
        ]
        return questions

    @classmethod
    def get_questions_story(cls)-> list[dict[str,Any]]:
        questions = [
            {
                "type": "text",
                "message": "enter story name",
                "name": "story_name",
                "default": "Suspicious Powershell Behavior",
            },
            {
                "type": "text",
                "message": "enter author name",
                "name": "story_author",
            },
            {
                "type": "checkbox",
                "message": "select a category",
                "name": "category",
                "choices": [
                    "Adversary Tactics",
                    "Account Compromise",
                    "Unauthorized Software",
                    "Best Practices",
                    "Cloud Security",
                    "Command and Control",
                    "Lateral Movement",
                    "Ransomware",
                    "Privilege Escalation",
                ],
            },
            {
                "type": "select",
                "message": "select a use case",
                "name": "usecase",
                "choices": [
                    "Advanced Threat Detection",
                    "Security Monitoring",
                    "Compliance",
                    "Insider Threat",
                    "Application Security",
                    "Other",
                ],
            },
        ]
        return questions
