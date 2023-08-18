
from contentctl.input.detection_builder import DetectionBuilder
from contentctl.objects.config import ConfigDetectionConfiguration
from contentctl.objects.detection import Detection
from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.enums import AnalyticsType


def test_add_deployment():
    detection = Detection(
        name="test detection",
        type=AnalyticsType.correlation.name,
        status="experimental",
        data_source=[],
        search="",
        how_to_implement="",
        known_false_positives="",
        references=[],
        tags=DetectionTags(
            name="test detection",
            observable=[],
            analytic_story=[],
            asset_type='foo',
            confidence=1,
            impact=1,
            risk_score=0.01,
            message='',
            product=[],
            required_fields=[],
            security_domain='access',
        ),
        deployment=ConfigDetectionConfiguration(),
    )
    detection.deployment.notable.rule_title = 'specific title'
    default_config = ConfigDetectionConfiguration()
    default_config.notable.rule_title = 'default title'
    builder = DetectionBuilder()
    builder.security_content_obj = detection
    builder.addDeployment(default_config)

    assert detection.deployment.notable.rule_title == 'specific title'
