import typing

from scapy.packet import Packet

from .analyzer import Analyzer
from ..data import IntrusionReport


class LogAnalyzer(Analyzer):

	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		for pkt in pkts:
			print(pkt.summary())
		return []

	@property
	def filter(self):
		return None
