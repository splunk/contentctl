class NewContentQuestions:

    @classmethod
    def get_questions_detection(self) -> list:
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
                'choices': [
                    "OSQuery ES Process Events",
                    "Powershell 4104",
                    "Sysmon Event ID 1",
                    "Sysmon Event ID 3",
                    "Sysmon Event ID 5",
                    "Sysmon Event ID 6",
                    "Sysmon Event ID 7",
                    "Sysmon Event ID 8",
                    "Sysmon Event ID 9",
                    "Sysmon Event ID 10",
                    "Sysmon Event ID 11",
                    "Sysmon Event ID 13",
                    "Sysmon Event ID 15",
                    "Sysmon Event ID 20",
                    "Sysmon Event ID 21",
                    "Sysmon Event ID 22",
                    "Sysmon Event ID 23",
                    "Windows Security 4624",
                    "Windows Security 4625",
                    "Windows Security 4648",
                    "Windows Security 4663",
                    "Windows Security 4688",
                    "Windows Security 4698",
                    "Windows Security 4703",
                    "Windows Security 4720",
                    "Windows Security 4732",
                    "Windows Security 4738",
                    "Windows Security 4741",
                    "Windows Security 4742",
                    "Windows Security 4768",
                    "Windows Security 4769",
                    "Windows Security 4771",
                    "Windows Security 4776",
                    "Windows Security 4781",
                    "Windows Security 4798",
                    "Windows Security 5136",
                    "Windows Security 5145",
                    "Windows System 7045"
                ]
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
    def get_questions_story(self) -> list:
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
