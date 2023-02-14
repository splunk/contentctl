from bottle import route, run, template, Bottle, ServerAdapter
from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingViewController import (
    DetectionTestingViewController,
)
import tabulate
from typing import Union
from wsgiref.simple_server import make_server, WSGIRequestHandler


DEFAULT_WEB_UI_PORT = 8000


class SimpleWebServer(ServerAdapter):
    server = None

    def run(self, handler):
        class DontLog(WSGIRequestHandler):
            def log_request(*args, **kwargs):
                pass

            def log_exception(*args, **kwargs):
                print(f"Exception in Web View:\n\tARGS:{args}\n\t{kwargs}")

        self.options["handler_class"] = DontLog
        self.server = make_server(
            "localhost", DEFAULT_WEB_UI_PORT, handler, **self.options
        )

        self.server.serve_forever()


class DetectionTestingViewWeb(DetectionTestingViewController):
    bottleApp: Bottle = Bottle()
    server: SimpleWebServer = SimpleWebServer()

    class Config:
        arbitrary_types_allowed = True

    def setup(self):
        self.bottleApp.route("/", callback=self.showStatus)
        self.bottleApp.route("/status", callback=self.showStatus)
        self.bottleApp.route("/results", callback=self.showResults)
        self.bottleApp.route("/report", callback=self.createReport)

        print("Start bottle app")
        self.bottleApp.run(server=self.server)

    def stop(self):
        if self.server.server is None:
            print("Web Server is not running anyway - nothing to shut down")
            return

        self.server.server.shutdown()

    def showStatus(self, elapsed_seconds: Union[float, None] = None):
        print("run show status")
        # Status updated on page load
        headers = ["Varaible Name", "Variable Value"]
        data = [["Some Number", 0], ["Some String", "this is a string"]]
        table = tabulate.tabulate(data, headers=headers, tablefmt="html")
        return template(table)

    def showResults(self):
        # Results generated on page load
        return template("page for {{status}}", status="RESULTS")

    def createReport(self):
        # Report generated on page load
        return template("page for {{status}}", status="REPORT")
