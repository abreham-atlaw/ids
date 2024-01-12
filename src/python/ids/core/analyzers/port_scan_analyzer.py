import typing

from scapy.layers.inet import TCP, IP
from scapy.packet import Packet

from ids.lib.ids.analyzer import Analyzer
from ids.lib.ids.data import IntrusionReport


class PortScanAnalyzer(Analyzer):
	_filter_layer = TCP

	def __init__(self, *args, threshold: int = 10, **kwargs):
		super().__init__(*args, **kwargs)
		self.__threshold = threshold

	def __map_src_ports(self, pkts: typing.List[Packet]) -> typing.Dict[str, typing.List[int]]:
		src_ports = {}
		for pkt in pkts:
			if src_ports.get(pkt[IP].src) is None:
				src_ports[pkt[IP].src] = []
			src_ports[pkt[IP].src].append(pkt[TCP].dport)

		return src_ports

	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		src_ports = self.__map_src_ports(pkts)

		reports = []
		for src, ports in src_ports.items():
			if len(ports) > self.__threshold:
				report = IntrusionReport(
					type="Port Scan",
					details=f"Detected port scan from {src} (ports: {sorted(ports)})",
					source=src,
					level=IntrusionReport.Severity.low
				)
				reports.append(report)

		return reports
