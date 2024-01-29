import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))


from ids.di.core_providers import CoreProviders

if __name__ == "__main__":
	detector = CoreProviders.provide_detector()
	detector.start()
