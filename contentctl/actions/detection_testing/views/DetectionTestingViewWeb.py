from bottle import template, Bottle, ServerAdapter
from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

from wsgiref.simple_server import make_server, WSGIRequestHandler
import jinja2
import webbrowser
from threading import Thread

DEFAULT_WEB_UI_PORT = 7999

STATUS_TEMPLATE = """
<html>
<head>
<title>contentctl Test {{ percent_complete }}</title>
<script src="https://code.jquery.com/jquery-3.5.1.js"></script>
<script src="https://cdn.datatables.net/1.13.3/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.3/css/jquery.dataTables.min.css">
<script>
$(document).ready(function () {
    $("#results").DataTable();
    $("#runningTests").DataTable();
});
</script>
</head>
<body>
<table id="runningTests" class="display" style="width:100%">
    <thead>
        <tr>
            <th>Instance Name</th>
            <th>Current Test</th>
            <th>Search</th>
        </tr>
    </thead>
    <tbody>
        {% for containerName, data in currentTestingQueue.items() %}
        <tr>
            <td>{{ containerName }}</td>
            <td>{{ data["name"] }}</td>    
            <td>{{ data["search"] }}</td>    
        </tr>
        {% endfor %}
    </tbody>
</table>

<table id="results" class="display" style="width:100%">
    <thead>
        <tr>
            <th>Test Name</th>
            <th>Test SID</th>
            <th>Run Duration</th>
            <th>Message</th>
            <th>Success</th>
        </tr>
    </thead>
    <tbody>
        {% for detection in detections %}
        {% for test in detection.tests %}
        <tr>
            <td>{{ detection.name }}: {{ test.name }}</td>
            <td><a href="{{test.sid_link}}" target="_blank"/>SID</td>
            <td>{{ test.runDuration }}</td>
            <td>{{ test.message }}</td>
            {% if test.success %}
            <td>True</td>
            {% else %}
            <td style="font-weight: bold;background-color: #ff9999"><b>False</b></td>
            {% endif %}
            
        </tr>
        {% endfor %}
        {% endfor %}
    </tbody>
</table>
</body>
</hmtl>
"""


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
            self.host, DEFAULT_WEB_UI_PORT, handler, **self.options
        )

        self.server.serve_forever()


class DetectionTestingViewWeb(DetectionTestingView):
    bottleApp: Bottle = Bottle()
    server: SimpleWebServer = SimpleWebServer(host="0.0.0.0", port=DEFAULT_WEB_UI_PORT)

    class Config:
        arbitrary_types_allowed = True

    def setup(self):
        self.bottleApp.route("/", callback=self.showStatus)
        self.bottleApp.route("/status", callback=self.showStatus)
        self.bottleApp.route("/results", callback=self.showResults)
        self.bottleApp.route("/report", callback=self.createReport)

        t = Thread(
            target=self.bottleApp.run, daemon=True, kwargs=({"server": self.server})
        )
        t.start()

        try:
            webbrowser.open(f"http://{self.server.host}:{DEFAULT_WEB_UI_PORT}")
        except Exception as e:
            print(f"Could not open webbrowser for status page: {str(e)}")

    def stop(self):

        if self.server.server is None:
            print("Web Server is not running anyway - nothing to shut down")
            return

        # print("called web server shutdown")
        # self.server.server.shutdown()
        # print("finished calling web server shutdown")

    def showStatus(self, interval: int = 60):
        # Status updated on page load
        # get all the finished detections:

        jinja2_template = jinja2.Environment().from_string(STATUS_TEMPLATE)
        summary_dict = self.getSummaryObject(
            test_result_fields=["success", "message", "sid_link"]
        )

        res = jinja2_template.render(
            currentTestingQueue=self.sync_obj.currentTestingQueue,
            percent_complete=summary_dict.get("percent_complete", 0),
            detections=summary_dict["tested_detections"],
        )

        return template(res)

    def showResults(self):
        # Results generated on page load
        return template("page for {{status}}", status="RESULTS")

    def createReport(self):
        # Report generated on page load
        return template("page for {{status}}", status="REPORT")
