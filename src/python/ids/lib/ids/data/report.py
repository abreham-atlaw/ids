from dataclasses import dataclass, field

from datetime import datetime


@dataclass
class IntrusionReport:

	class Severity:
		low = 0
		moderate = 1
		high = 2

	type: str
	details: str
	source: str
	level: int
	time: datetime = field(default_factory=lambda: datetime.now())
