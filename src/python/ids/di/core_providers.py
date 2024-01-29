import typing
from ids.core.analyzers.ping_sweep_analyzer import PingSweepAnalyzer
from ids.core.analyzers.port_scan_analyzer import PortScanAnalyzer
from ids.core.analyzers.syn_flood_analyzer import SynFloodAnalyzer
from ids.core.config import CHUNK_SIZE, INTERFACE

from ids.lib.ids.analyzer import Analyzer, LogAnalyzer
from ids.lib.ids.detector import Detector
from ids.lib.ids.handler import IntrusionHandler, LogHandler


class CoreProviders:

	@staticmethod
	def provider_analyzers() -> typing.List[Analyzer]:
		return [
			LogAnalyzer(),
			PortScanAnalyzer(),
			PingSweepAnalyzer(),
			SynFloodAnalyzer()
		]

	@staticmethod
	def provide_handlers() -> typing.List[IntrusionHandler]:
		return [
			LogHandler()
		]

	@staticmethod
	def provide_detector() -> Detector:
		return Detector(
			analyzers=CoreProviders.provider_analyzers(),
			handlers=CoreProviders.provide_handlers(),
			interface=INTERFACE,
			chunk_size=CHUNK_SIZE
		)
