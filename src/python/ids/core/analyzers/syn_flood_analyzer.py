import typing
from scapy.layers.inet import IP, TCP

from scapy.packet import Packet

from ids.lib.ids.analyzer import Analyzer
from ids.lib.ids.data import IntrusionReport


class SynFloodAnalyzer(Analyzer):
	_filter_layer = TCP

	def __init__(self, *args, threshold=500, **kwargs):
		super().__init__(*args, **kwargs)
		self.__threshold = threshold

	@staticmethod
	def __count_src_syns(pkts: typing.List[Packet]) -> typing.Dict[str, int]:
		counts = {}
		for pkt in pkts:
			if pkt[TCP].flags != "S":
				continue
			if counts.get(pkt[IP].src) is None:
				counts[pkt[IP].src] = 0
			counts[pkt[IP].src] += 1
		return counts

	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:

		syn_counts = self.__count_src_syns(pkts)

		reports = []
		for src, count in syn_counts.items():
			if count > self.__threshold:
				report = IntrusionReport(
					type="SYN Flood",
					details=f"Detected SYN flood from {src} (SYN packets: {count})",
					source=src,
					level=IntrusionReport.Severity.high
				)
				reports.append(report)

		return reports
