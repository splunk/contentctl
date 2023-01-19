from bottle import route, run, template, Bottle
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewController import (
    DetectionTestingViewController,
)
import tabulate


DEFAULT_WEB_UI_PORT = 9999


class DetectionTestingViewWeb(DetectionTestingViewController):
    refresh_count: int = 0
    bottleApp: Bottle = Bottle()

    class Config:
        arbitrary_types_allowed = True

    def setup(self):
        self.bottleApp.route("/", callback=self.showStatus)
        self.bottleApp.route("/status", callback=self.showStatus)
        self.bottleApp.route("/results", callback=self.showResults)
        self.bottleApp.route("/report", callback=self.createReport)
        self.bottleApp.run(host="localhost", port=9999)

    def showStatus(self, elapsed_seconds: float = 60):
        # Status updated on page load
        headers = ["Varaible Name", "Variable Value"]
        data = [
            ["Some Number", 0],
            ["Some String", "this is a string"],
            ["Refresh Count", self.refresh_count],
        ]
        self.refresh_count += 1
        table = tabulate.tabulate(data, headers=headers, tablefmt="html")
        return template(table)

    def showResults(self):
        # Results generated on page load
        return template("results for {{status}}", status="RESULTS")

    def createReport(self):
        # Report generated on page load
        return template("results for {{status}}", status="REPORT")
