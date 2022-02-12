#!/usr/bin/env python
import hmac
import os
from hashlib import sha256
from time import time

import requests
from yaml import load, CLoader

"""
Here's a Tuya api client example in python:
    https://github.com/tuya/tuya-iot-python-sdk/blob/4c183a8bb5157c0b6166b891a48a247095cecba9/tuya_iot/openapi.py#L90

There's a go example in the Tuya api docs
"""

class Tuya:

    def __init__(self, auth_token="", refresh_token=""):
        with open("config.yaml") as f:
            config = load(f, Loader=CLoader)

        self.host = config["api"]["host"]
        self.api_key = os.environ.get("TUYA_KEY") # aka client id in docs
        self.api_secret = os.environ.get("TUYA_SECRET")
        self.access_token = auth_token # generally acquire this via get_token\
        self.refresh_token = refresh_token

    @staticmethod
    def get_time():
        """
        required for signature algo

        :param self:
        :return:
        """
        return round(1000 * time())

    @staticmethod
    def generate_string_to_sign(method, request_path, request_query, body="", **required_arguments):
        """
           formats the data request specific data required by the signature
           algorithm as defined in the API docs.

           request path is the API endpoint path, e.g.

             /v1.0/token

           request query is the query part of the request, e.g. (includes the question mark
           in this example)

             ?grant_type=1

           body is the body of the request (form format I think)

           required arguments is a dictionary of arguments/parameters required by
           the api endpoint, e.g.

             {"ara_id": "abc123", "call_id": "456def"}

           NB: that dict must be sorted lexicographically based on the keys

           :return:
           """

        body_sha = sha256(body.encode("utf-8")).hexdigest()
        url = request_path + request_query
        s = sorted(required_arguments.items())  # no sorting function provided as param to sorted func intentionally

        canonical_header_string = ""
        for k, v in s:
            canonical_header_string += f"{k}:{v}" + "\n"

        # NB: the format requires TWO new lines after the last param and
        # before the url, which is why there's an extra "\n" after appending
        # the value of the temporary string variable "t"
        rd = method.upper() + "\n" + \
             body_sha + "\n" + \
             canonical_header_string + "\n" + \
             url

        return rd

    def generate_message_to_sign(self, method, request_path, request_query, body="", nonce = "", **required_arguments):
        """
        returns the data (string) that is to be signed, which is NOT
        the so-called "string to sign" mentioned in the API docs, but
        it does depend on string-to-sign.

        from api docs string is:

            client_id + sig_time + nonce + sig_string

        :return:
        """

        tyme = Tuya.get_time()
        string_to_sign = Tuya.generate_string_to_sign(method, request_path, request_query, body, **required_arguments)

        # join the strings as required, filtering empty strings, b/c apparently
        # python doesn't like that?
        msg = ''.join(filter(None, [self.api_key, self.access_token, str(tyme), string_to_sign]))

        return msg, tyme

    def generate_signature(self, message):
            """
                returns the signature data, which depends on

                docs: https://developer.tuya.com/en/docs/iot/singnature?id=Ka43a5mtx1gsc

                :param message:
                :param key:
                :return:
                """

            key_bytes = bytes(self.api_secret, "utf-8")
            encoded_string = message.encode("utf-8")

            return hmac.new(key=key_bytes, msg=encoded_string, digestmod='sha256').hexdigest().upper()

    def get_auth_token(self):
        """
        Gets a limited lifetime token for subsequent calls to the API.  This is documented
        in the "Industrial General" API documentation section

        this endpoint does not have required parameters - at least
        not required for the signature

        :return:
        """

        protocol = "https://"
        path = "/v1.0/token"
        query = "?grant_type=1" # todo add to request and generate
        url = protocol + self.host + path + query

        msg, tyme = self.generate_message_to_sign("get", path, query) # no required params for this endpoint
        sig = self.generate_signature(msg)

        headers = {"client_id": self.api_key,
                   "sign_method": "HMAC-SHA256",
                   "t": str(tyme),
                   "sign": sig}

        if self.access_token != "":
            headers["access_token"] = self.access_token

        r = requests.get(url, headers=headers)

        if r.status_code == 200:
            return r.status_code, \
                   r.json()["result"]["access_token"], \
                   r.json()["result"]["refresh_token"], \
                   r.json()["result"]["expire_time"]

        return r.status_code, "", "", ""

    def get_devices(self):
        path = "/v2.0/devices"
        url = "https://" + self.host + path
        print(f"get devs url is: {url}")

    @staticmethod
    def get_time():
        return round(1000 * time())


if __name__ == "__main__":

    t = Tuya()

    status, access, refresh, t_expire = t.get_auth_token()

    if status == 200:
        t.access_token = access # todo make properties
        t.refresh_token = refresh
