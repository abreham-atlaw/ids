from abc import ABC, abstractmethod

from ids.lib.ids.data import IntrusionReport


class IntrusionHandler(ABC):

	@abstractmethod
	def handle(self, report: IntrusionReport):
		pass
