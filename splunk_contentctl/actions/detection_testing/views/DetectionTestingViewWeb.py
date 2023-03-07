from bottle import route, run, template, Bottle, ServerAdapter
from splunk_contentctl.actions.detection_testing.views.DetectionTestingView import (
    DetectionTestingView,
)

from splunk_contentctl.objects.unit_test_result import UnitTestResult
from wsgiref.simple_server import make_server, WSGIRequestHandler


DEFAULT_WEB_UI_PORT = 7999
STATUS_TEMPLATE_ONE = """
{% for detection in detections %}
    <table>
    <tr>
        <td><b>Name</b></td>
        <td>{{ detection.name }}</td>
    </tr>
    <tr>
        <td>Search</td>
        <td><code>{{ detection.search }}</code></td>
    </tr>
    <tr><td><i>Tests</i></td></tr>
    {% for test in detection.tests %}
    <tr>
        <td>{{ test.name }}</td>
        <td>{{ test.message }}</td>
    </tr>
    
    <tr>
        <td>SID</td>
        <td><a href="{{ test.sid_link }}" />{{ test.sid_link }}</td>
    </tr>
    <tr>
        <td>Duration</td>
        <td>{{ test.runDuration }} seconds</td>
    </tr>
    {% endfor %}
</table><br/>
{% endfor %}
"""

STATUS_TEMPLATE = """
<html>
<head>
<script src="https://code.jquery.com/jquery-3.5.1.js"></script>
<script src="https://cdn.datatables.net/1.13.3/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.3/css/jquery.dataTables.min.css">
<script>
$(document).ready(function () {
    $("#results").DataTable();
});
</script>
</head>
<body>
<table id="results" class="display" style="width:100%">
    <thead>
        <tr>
            <th>Test Name</th>
            <th>Test SID</th>
            <th>Run Duration</th>
            <th>Test Result</th>
        </tr>
    </thead>
    <tbody>
        {% for detection in detections %}
        {% for test in detection.tests %}
        <tr>
            <td>{{ test.name }}</td>
            <td><a href="{{test.sid_link}}" />SID</td>
            <td>{{ test.runDuration }}s</td>

            
            {% if 'TEST PASSED' in test.message %}
            <td>{{ test.message }}</td>
            {% else %}
            <td style="font-weight: bold;background-color: #ff9999"><b>{{ test.message }}</b></td>
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

        # print("called web server shutdown")
        self.server.server.shutdown()
        # print("finished calling web server shutdown")

    def showStatus(self, interval: int = 60):
        # Status updated on page load
        # get all the finished detections:
        import jinja2

        jinja2_template = jinja2.Environment().from_string(STATUS_TEMPLATE)
        tables = []
        finished_detections = self.sync_obj.outputQueue[:]
        detection_dicts = []
        import pprint

        for d in finished_detections:
            res = {}
            res["name"] = d.name
            res["search"] = d.search
            res["tests"] = []
            fail = False
            for t in d.test.tests:
                try:
                    test_dict = t.result.get_summary_dict()
                except Exception as e:
                    print(f"result is none for detection {d} and test {t}")
                    faill = True
                    break

                test_dict["name"] = t.name
                res["tests"].append(test_dict)

            if not fail:
                detection_dicts.append(res)

        res = jinja2_template.render(detections=detection_dicts)

        return template(res)

    def showResults(self):
        # Results generated on page load
        return template("page for {{status}}", status="RESULTS")

    def createReport(self):
        # Report generated on page load
        return template("page for {{status}}", status="REPORT")
