import typing
from abc import ABC, abstractmethod

from scapy.packet import Packet

from ids.lib.ids.data.report import IntrusionReport


class Analyzer(ABC):

	_filter_layer = None

	def _filter(self, pkts: typing.List[Packet]) -> typing.List[Packet]:
		if self._filter_layer is None:
			return pkts
		return [pkt for pkt in pkts if self._filter_layer in pkt]

	@abstractmethod
	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		pass

	def analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		return self._analyze(self._filter(pkts))
