import typing
from scapy.layers.inet import IP, ICMP
from collections import defaultdict

from scapy.packet import Packet

from ids.lib.ids.analyzer import Analyzer
from ids.lib.ids.data import IntrusionReport


class DoSAnalyzer(Analyzer):

	_filter_layer = IP

	def __init__(self, *args, threshold: int=int(2e3), **kwargs):
		super().__init__(*args, **kwargs)
		self.__threshold = threshold

	@staticmethod
	def __map_rates(pkts: typing.List[Packet]) -> typing.Dict[str, typing.Set[str]]:
		pkts = sorted(pkts, key=lambda pkt: pkt.time)
		
		rates = {}
		initial_times = {}
		counts = {}


		for pkt in pkts:
			src = pkt[IP].src
			if initial_times.get(src) is None:
				initial_times[src] = pkt.time
				counts[src] = 1
				continue
			counts[src] += 1
			rates[src] = counts[src]/((pkt.time - initial_times[src]) + 1e-9)
		
		return rates


	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:

		rates = self.__map_rates(pkts)

		reports = []
		for src, rate in rates.items():
			if rate > self.__threshold:
				report = IntrusionReport(
					type="DoS",
					details=f"Detected DoS from {src} (request rate: {rate})",
					source=src,
					level=IntrusionReport.Severity.moderate
				)
				reports.append(report)

		return reports
