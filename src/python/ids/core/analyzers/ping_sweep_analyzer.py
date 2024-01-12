import typing
from scapy.layers.inet import IP, ICMP
from collections import defaultdict

from scapy.packet import Packet

from ids.lib.ids.analyzer import Analyzer
from ids.lib.ids.data import IntrusionReport


class PingSweepAnalyzer(Analyzer):
	_filter_layer = ICMP

	def __init__(self, *args, threshold: int=10, **kwargs):
		super().__init__(*args, **kwargs)
		self.__threshold = threshold

	@staticmethod
	def __map_src_dest(pkts: typing.List[Packet]) -> typing.Dict[str, typing.List[str]]:
		src_dests = {}

		for pkt in pkts:
			if pkt[ICMP].type != 8:
				continue
			if src_dests.get(pkt[IP].src) is None:
				src_dests[pkt[IP].src] = []
			src_dests.get(pkt[IP].src).append(pkt[IP].dst)

		return src_dests

	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:

		src_dests = self.__map_src_dest(pkts)

		reports = []
		for src, dests in src_dests.items():
			if len(dests) > self.__threshold:
				report = IntrusionReport(
					type="Ping Sweep",
					details=f"Detected ping sweep from {src} (destinations: {sorted(dests)})",
					source=src,
					level=IntrusionReport.Severity.low
				)
				reports.append(report)

		return reports
