#!/usr/bin/env python
import os

from time import time

def signature_time():
    return round(1000 * time())

def get_creds():
    return os.environ.get("TUYA_KEY"), os.environ.get("TUYA_SECRET")

class Tuya:
    host = "openapi.tuyaus.com"
    def __init__(self):
        pass

    def get_devices(self):
        path = "/v2.0/devices"
        url = "https://" + self.host + path
        print(f"get devs url is: {url}")

if __name__ == "__main__":
    print(f"sig time is: {signature_time()}")
    print(f"creds are: {get_creds()}")
