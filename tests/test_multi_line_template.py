from configparser import RawConfigParser
import pathlib
from contentctl.objects.config import Config, ConfigNotable
from contentctl.objects.deployment import Deployment
from contentctl.objects.deployment_scheduling import DeploymentScheduling
from contentctl.objects.detection import Detection
from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.enums import SecurityContentType
from contentctl.output.conf_output import ConfOutput


def test_template_render_parse(tmp_path):
    search = """test
test1
foooooo
bar"""
    tmpdir = tmp_path
    input_path = tmpdir
    config = Config()
    detections = [
        Detection(
            name="foo",
            search=search,
            type="Correlation",
            status="experimental",
            data_source=[],
            how_to_implement="",
            known_false_positives="",
            references=[],
            deployment=Deployment(
                scheduling=DeploymentScheduling(
                    cron_schedule="0 * * * * *",
                    earliest_time="-70m@m",
                    latest_time="-10m@m",
                    schedule_window="auto",
                ),
                notable=ConfigNotable(
                    rule_description="%description%",
                    rule_title="%name%",
                    nes_fields=["foo", "bar"],
                ),
            ),
            tags=DetectionTags(
                name="foo",
                analytic_story=[],
                observable=[],
                asset_type="",
                confidence=100,
                impact=100,
                risk_score=100,
                message="",
                required_fields=[],
                security_domain="access",
                product=[],
            ),
        ),
    ]
    conf_output = ConfOutput(input_path, config)
    conf_output.writeHeaders()
    conf_output.writeObjects(detections, SecurityContentType.detections)
    app_path = pathlib.Path(config.build.path_root) / config.build.name
    conf_path = app_path / "default" / "savedsearches.conf"
    parser = RawConfigParser()
    with open(conf_path, "r") as conf_data_file:
        conf_data = conf_data_file.read()

    # ConfigParser cannot read multipleline strings that simply escape the newline character with \
    # To include a newline, you need to include a space at the beginning of the newline.
    # We will simply replace all \NEWLINE with NEWLINESPACE (removing the leading literal \).
    # We will discuss whether we intend to make these changes to the underlying conf files
    # or just apply the changes here
    conf_data = conf_data.replace("\\\n", "\n ")

    parser.read_string(conf_data)
    section = parser.sections()[0]
    assert parser[section]["search"] == search
