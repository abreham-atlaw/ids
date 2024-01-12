import typing

from ids.lib.ids.analyzer import Analyzer, LogAnalyzer
from ids.lib.ids.detector import Detector
from ids.lib.ids.handler import IntrusionHandler, LogHandler


class CoreProviders:

	@staticmethod
	def provider_analyzers() -> typing.List[Analyzer]:
		return [
			LogAnalyzer()
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
			handlers=CoreProviders.provide_handlers()
		)
