import typing
from abc import ABC, abstractmethod

from scapy.layers.inet import IP
from scapy.packet import Packet

import socket

from ids.lib.ids.data.report import IntrusionReport


class Analyzer(ABC):

	class PacketDirection:
		incoming = 0
		outgoing = 1
		all = 2

	_filter_layer = None
	_filter_direction = PacketDirection.all

	def __init__(self, host_ip=None) -> None:
		super().__init__()
		if host_ip is None:
			host_ip = self.__get_host_ip()
		self._host_ip = host_ip
			
	@staticmethod
	def __get_host_ip() -> str:
		hostname = socket.gethostname()
		local_ip = socket.gethostbyname(hostname)
		return local_ip

	def __filter_direction(self, pkts: typing.List[Packet]) -> typing.List[Packet]:
		if self._filter_direction == Analyzer.PacketDirection.all:
			return pkts
		
		pkts = [
			pkt
			for pkt in pkts
			if IP in pkt
		]

		if self._filter_direction == Analyzer.PacketDirection.incoming:
			return [
				pkt
				for pkt in pkts
				if pkt[IP].src != self._host_ip
			]
		
		return [
				pkt
				for pkt in pkts
				if pkt[IP].src == self._host_ip
			]

	def _filter(self, pkts: typing.List[Packet]) -> typing.List[Packet]:
		pkts = self.__filter_direction(pkts)
		if self._filter_layer is None:
			return pkts
		return [pkt for pkt in pkts if self._filter_layer in pkt]

	@abstractmethod
	def _analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		pass

	def analyze(self, pkts: typing.List[Packet]) -> typing.List[IntrusionReport]:
		return self._analyze(self._filter(pkts))
