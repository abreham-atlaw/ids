import typing

from scapy.packet import Packet
from scapy.sendrecv import sniff

from ids.lib.ids.analyzer import Analyzer
from ids.lib.ids.data import IntrusionReport
from ids.lib.ids.handler import IntrusionHandler


class Detector:

	def __init__(
			self,
			analyzers: typing.List[Analyzer],
			handlers: typing.List[IntrusionHandler],
			chunk_size=100,
			interface: str=None
	):
		self.__analyzers = analyzers
		self.__chunk_size = chunk_size
		self.__handlers = handlers
		self.__interface = interface

	def __analyze_packets(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		reports = []
		for analyzer in self.__analyzers:
			reports.extend(analyzer.analyze(pkts))

		return reports

	def __handle_reports(self, reports: typing.List[IntrusionReport]):
		for handler in self.__handlers:
			for report in reports:
				handler.handle(report)

	def __handle_chunk(self, pkts: typing.List[Packet]):
		reports = self.__analyze_packets(pkts)
		self.__handle_reports(reports)

	def start(self):
		print("[+]Starting listening...")
		while True:
			chunk = sniff(count=self.__chunk_size, iface=self.__interface)
			self.__handle_chunk(list(chunk))
