
from __future__ import annotations
from pydantic import BaseModel

class DeploymentJira(BaseModel):
    account: str
    jira_attachment: str
    jira_dedup: str
    jira_dedup_content: str
    jira_description: str
    jira_project: str
    jira_issue_type: str
    jira_priority: str
    jira_priority_dynamic: str
    jira_summary: str
