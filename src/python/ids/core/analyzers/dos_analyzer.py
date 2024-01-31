import typing
from scapy.layers.inet import IP, ICMP
from collections import defaultdict

from scapy.packet import Packet

from ids.lib.ids.analyzer import Analyzer
from ids.lib.ids.data import IntrusionReport


class DoSAnalyzer(Analyzer):

	_filter_layer = IP
	_filter_direction = Analyzer.PacketDirection.incoming

	def __init__(self, *args, threshold: int=100, count_threshold=100, **kwargs):
		super().__init__(*args, **kwargs)
		self.__threshold = threshold
		self.__count_threshold = count_threshold

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
		
		return rates, counts


	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:

		rates, counts = self.__map_rates(pkts)

		reports = []
		for src in rates.keys():
			if rates[src] > self.__threshold and counts[src] > self.__count_threshold:
				report = IntrusionReport(
					type="DoS",
					details=f"Detected DoS from {src} (request rate: {rates[src]})",
					source=src,
					level=IntrusionReport.Severity.moderate
				)
				reports.append(report)

		return reports
