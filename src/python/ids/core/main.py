from ids.di.core_providers import CoreProviders

if __name__ == "__main__":
	detector = CoreProviders.provide_detector()
	detector.start()
