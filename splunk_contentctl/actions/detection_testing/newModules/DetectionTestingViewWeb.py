from bottle import route, run, template, Bottle
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewController import (
    DetectionTestingViewController,
)
import tabulate
from typing import Union
from threading import Thread

DEFAULT_WEB_UI_PORT = 9999


class DetectionTestingViewWeb(DetectionTestingViewController):
    bottleApp: Bottle = Bottle()
    thread: Union[Thread, None] = None

    class Config:
        arbitrary_types_allowed = True

    def setup(self):
        self.bottleApp.route("/", callback=self.showStatus)
        self.bottleApp.route("/status", callback=self.showStatus)
        self.bottleApp.route("/results", callback=self.showResults)
        self.bottleApp.route("/report", callback=self.createReport)

        self.thread = Thread(
            target=self.bottleApp.run,
            kwargs={"host": "localhost", "port": 9999},
            daemon=True,
        )
        # Must run the server as a thread in the background
        self.thread.start()

    def showStatus(self, elapsed_seconds: Union[float, None] = None):

        # Status updated on page load
        headers = ["Varaible Name", "Variable Value"]
        data = [["Some Number", 0], ["Some String", "this is a string"]]
        table = tabulate.tabulate(data, headers=headers, tablefmt="html")
        return template(table)

    def showResults(self):
        # Results generated on page load
        return template("results for {{status}}", status="RESULTS")

    def createReport(self):
        # Report generated on page load
        return template("results for {{status}}", status="REPORT")
