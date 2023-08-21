
from contentctl.input.detection_builder import DetectionBuilder
from contentctl.objects.config import ConfigDetectionConfiguration, ConfigNotable
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
        deployment=ConfigDetectionConfiguration.parse_obj({
            'notable': {
                'rule_title': 'specific title',
                'rule_description': 'desc',
                'nes_fields': []
            }
        }),
    )
    default_config = ConfigDetectionConfiguration.parse_obj({
        'notable': {
            'rule_title': 'default title',
            'rule_description': 'desc',
            'nes_fields': [],
        }
    })
    builder = DetectionBuilder()
    builder.security_content_obj = detection
    builder.addDeployment(default_config)

    assert detection.deployment.notable.rule_title == 'specific title'

def test_add_nes_fields():
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
        deployment=ConfigDetectionConfiguration(
            notable=ConfigNotable(rule_title='foo', rule_description='bar', nes_fields=['foo', 'bar'])
        ),
    )
    default_config = ConfigDetectionConfiguration()
    builder = DetectionBuilder()
    builder.security_content_obj = detection
    builder.addDeployment(default_config)
    builder.addNesFields()

    assert detection.nes_fields == 'foo,bar'
