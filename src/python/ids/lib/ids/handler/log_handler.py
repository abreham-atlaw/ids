from ids.lib.ids.data import IntrusionReport
from ids.lib.ids.handler.handler import IntrusionHandler


class LogHandler(IntrusionHandler):

	def handle(self, report: IntrusionReport):
		print(f"""
[+]Intrusion Detected
\t\tTime: {report.time}
\t\tLevel: {report.level}
\t\tType: {report.type}
\t\tSource: {report.source}
\t\tDetails: {report.details}
""")
