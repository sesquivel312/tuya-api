#!/usr/bin/env python
import hmac
import os
from hashlib import sha256
from time import time

from yaml import load, CLoader

def get_time():
    return round(1000 * time())

def get_creds():
    return os.environ.get("TUYA_KEY"), os.environ.get("TUYA_SECRET")

ep_sig_test_users = "/v2.0/apps/schema/users"
ep_sig_test_token = "/v1.0/token"
query_token = "?grant_type=1"
method = "GET"
client_id = "1KAD46OrT9HafiKdsXeg" # from cloud UI
access_token = "3f4eda2bdec17232f67c0b188af3eec1" # would I have this when getting a token for the "first time"
secret = "4OHBOnWOqaEC1mWXOpVL3yV50s0qGSRC" # where does this come from?
body = ""
t = 1588925778000 # would normally be from signature_time()
nonce = "5138cc3a9033d69856923fd07b491173"
sig_headers = "area_id:call_id" # how would I know what headers to use? are these http headers or are they parts of a url?
area_id = "29a33e8796834b1efa6" # I assume this is specific to the users api endpoint
call_id = "8afdb70ab2ed11eb85290242ac130003" # I also assume this is specific to the api endpoint
area_id_string = f"area_id:{area_id}"
call_id_string = f"call_id:{call_id}"
pgnum = "1"
page_size = "50"

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
    s = sorted(required_arguments.items()) # no sorting function provided as param to sorted func intentionally

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

def generate_message_to_sign(time, nonce, method, request_path, request_query, body="", **required_arguments):
    """
    returns the data (string) that is to be signed, which is NOT
    the so called "string to sign" mentioned in the API docs, but
    it does depend on string-to-sign.

    :return:
    """
    # client_id + sig_time + nonce + sig_string
    return client_id + str(time) + nonce + format_request_data(method, request_path, request_query, body, **required_arguments)

def gen_sig(message, key):
    """
    returns the signature data, which depends on

    :param message:
    :param key:
    :return:
    """

    key_bytes = bytes(key, "utf-8")
    encoded_string = message.encode("utf-8")
    return hmac.new(key=key_bytes, msg=encoded_string, digestmod='sha256').hexdigest().upper()

class Tuya:

    def __init__(self):
        with open("config.yaml") as f:
            config = load(f, Loader=CLoader)

        self.host = config["api"]["host"]
        self.api_client_id = os.environ.get("TUYA_KEY")
        self.api_client_secret = os.environ.get("TUYA_SECRET")

    def generate_string_to_sign(self, t):
        pass

    def generate_signature(self, t, key):
        nonce = ""  # todo need a nonce generator?
        s = self.api_client_id + str(t) + nonce + ""
        return client_id + str()

    def get_auth_token(self):
        path = "/v1.0/token"
        query = {"grant_type": "1"}

    def get_devices(self):
        path = "/v2.0/devices"
        url = "https://" + self.host + path
        print(f"get devs url is: {url}")

if __name__ == "__main__":

    required_args = {
        "call_id": "8afdb70ab2ed11eb85290242ac130003",
        "area_id": "29a33e8796834b1efa6"

    }
    m = generate_message_to_sign(t, nonce, method, ep_sig_test_token, query_token, body, **required_args)
    print(gen_sig(m, secret))
