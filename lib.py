#!/usr/bin/env python
import hmac
import os
from hashlib import sha256
from time import time

import requests
from yaml import load, CLoader

def get_time():
    return round(1000 * time())


class Tuya:

    def __init__(self, auth_token=""):
        with open("config.yaml") as f:
            config = load(f, Loader=CLoader)

        self.host = config["api"]["host"]
        self.api_key = os.environ.get("TUYA_KEY") # aka client id in docs
        self.api_secret = os.environ.get("TUYA_SECRET")
        self.auth_token = auth_token # generally acquire this via get_token

        # other stuff I might need to add
        #   temp token - issued after auth to API - limited lifetime I think

    @staticmethod
    def get_time():
        """
        required for signature algo

        :param self:
        :return:
        """
        return round(1000 * time())

    @staticmethod
    def format_request_data(method, request_path, request_query, body="", **required_arguments):
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

        t = ""
        for k, v in s:
            t += f"{k}:{v}" + "\n"

        # NB: the format requires TWO new lines after the last param and
        # before the url, which is why there's an extra "\n" after appending
        # the value of the temporary string variable "t"
        tt = method.upper() + "\n" + \
             body_sha + "\n" + \
             t + "\n" + \
             url

        return tt

    def generate_message_to_sign(self, time, method, request_path, request_query, body="", nonce = "", **required_arguments):
        """
        returns the data (string) that is to be signed, which is NOT
        the so-called "string to sign" mentioned in the API docs, but
        it does depend on string-to-sign.

        from api docs string is:

            client_id + sig_time + nonce + sig_string

        :return:
        """

        t = self.api_key + \
            str(time) + \
            self.auth_token + \
            nonce + \
            Tuya.format_request_data(method, request_path, request_query, body, **required_arguments)

        return t

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

        grant_type is a required query parameter - i.e. it's used to
        sign the request

        :return:
        """
        path = "/v1.0/token"
        query = "?grant_type=1"
        req_params = {"grant_type": "1"}
        url = "https://" + self.host + path + query

        tyme = Tuya.get_time()
        print("@@@ calling generate message")
        msg = self.generate_message_to_sign(tyme, "get", path, query, **req_params)
        print("@@@ calling generate sig")
        sig = self.generate_signature(msg)

        headers = {"client_id": self.api_key,
                   "sign_method": "HMAC-SHA256",
                   "t": str(tyme),
                   "sign": sig} # todo conditionally add access token


        print("@@@ about to call requests")
        r = requests.get(url, headers=headers)

        print(f"status: {r.status_code}, text: {r.text}")

    def get_devices(self):
        path = "/v2.0/devices"
        url = "https://" + self.host + path
        print(f"get devs url is: {url}")

if __name__ == "__main__":

    t = Tuya()

    t.get_auth_token()

    # todo check this example for what I'm doing wrong w/the API: https://github.com/tuya/tuya-iot-python-sdk/blob/4c183a8bb5157c0b6166b891a48a247095cecba9/tuya_iot/openapi.py#L90
