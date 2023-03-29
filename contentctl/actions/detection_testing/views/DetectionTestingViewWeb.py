from bottle import route, run, template, Bottle, ServerAdapter
from contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

from contentctl.objects.unit_test_result import UnitTestResult
from wsgiref.simple_server import make_server, WSGIRequestHandler
import jinja2
import webbrowser
from threading import Thread
import json, websocket

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
<td>{{ test.name }}</td>
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
            "localhost", DEFAULT_WEB_UI_PORT, handler, **self.options
        )

        self.server.serve_forever()


class DetectionTestingViewWeb(DetectionTestingView):
    bottleApp: Bottle = Bottle()
    server: SimpleWebServer = SimpleWebServer()

    class Config:
        arbitrary_types_allowed = True

    def setup(self):
        WS_URL = "ws://localhost:8000"

        # Define the data you want to send to the Streamlit app
        summary_dict = self.getSummaryObject(
            test_model_fields=["success", "message", "sid_link"]
        )

        currentTestingQueue=self.sync_obj.currentTestingQueue,
        percent_complete=summary_dict.get("percent_complete", 0),
        detections=summary_dict["tested_detections"],
        
        x = {"currentTestingQueue": currentTestingQueue, 
            "percent_complete": percent_complete,
            "detections": detections}

        data = json.dumps(x)

        # Create the WebSocket client
        ws = websocket.WebSocket()
        ws.connect(WS_URL)

        # Send the data to the Streamlit app
        ws.send(json.dumps(data))

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
            test_model_fields=["success", "message", "sid_link"]
        )

        res = jinja2_template.render(
            currentTestingQueue=self.sync_obj.currentTestingQueue,
            percent_complete=summary_dict.get("percent_complete", 0),
            detections=summary_dict["tested_detections"],
        )

        return template(res)
   
    def txdata(self):
        # Status updated on page load
        # get all the finished detections:
         # Define the WebSocket server URL
       pass


    def showResults(self):
        # Results generated on page load
        return template("page for {{status}}", status="RESULTS")

    def createReport(self):
        # Report generated on page load
        return template("page for {{status}}", status="REPORT")
