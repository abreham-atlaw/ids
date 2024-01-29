from ids.lib.ids.data import IntrusionReport
from ids.lib.ids.handler.handler import IntrusionHandler


class LogHandler(IntrusionHandler):

	def handle(self, report: IntrusionReport):
		print(f"""
[+]Intrusion Detected
\tTime: {report.time}
\tLevel: {report.level}
\tType: {report.type}
\tSource: {report.source}
\tDetails: {report.details}
""")
