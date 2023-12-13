
import uuid
import string



from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.deployment_scheduling import DeploymentScheduling
from contentctl.objects.deployment_email import DeploymentEmail
from contentctl.objects.deployment_notable import DeploymentNotable
from contentctl.objects.deployment_rba import DeploymentRBA
from contentctl.objects.deployment_slack import DeploymentSlack
from contentctl.objects.deployment_phantom import DeploymentPhantom
class Deployment(SecurityContentObject):
    name: str = "PLACEHOLDER_NAME"
    #id: str = None
    #date: str = None
    #author: str = None
    #description: str = None
    #contentType: SecurityContentType = SecurityContentType.deployments
    scheduling: DeploymentScheduling = None
    email: DeploymentEmail = None
    notable: DeploymentNotable = None
    rba: DeploymentRBA = None
    slack: DeploymentSlack = None
    phantom: DeploymentPhantom = None
    tags: dict = None
    