#!/usr/bin/env python

from hashlib import sha256
import hmac

import requests

import lib

protocol = "https://"
host = "openapi.tuyaus.com"
ep_devices = "/v2.0/devices"
ep_get_token = "/v1.0/token"
url_devices = protocol + host + ep_devices
url_get_token = protocol + host + ep_get_token

s = requests.Session()
s.auth = lib.get_creds()
r = s.get(url_get_token)

# signature for token management
# hash( client_id + sig_time + nonce + sig_string, secret).upper()
# client_id: get from cloud UI
# nonce - may be optional
# sig_string:
#   httpmethod.upper() \n +
#   sha256(body) \n +
#   headers \n\n + << yes double new lines!!!
#   url
#
# include sha(body) only if request is not a form
#
# headers: the headers to include in the signature - names only
#   in the format:  signature-headers: name1:name2:...
#   any header name not listed is not include in the signature
#   uh, how do I know which to include?
#
# url = path_component + query_components
#   query_components = ?key1=val1&...&keyn=valn << sorted


# sig test from https://developer.tuya.com/en/docs/iot/singnature?id=Ka43a5mtx1gsc
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

def get_sig_string():
    body_sha = sha256(body.encode("utf-8")).hexdigest()
    url = ep_sig_test_token + query_token

    # NB the headers - which I think are actually query keys and values - are sorted!!!
    return method.upper() + "\n"  + \
           body_sha + "\n" + \
           area_id_string + "\n" + \
           call_id_string + "\n\n" + \
           url


def get_string_to_hash():
    # client_id + sig_time + nonce + sig_string
    return client_id + str(t) + nonce + get_sig_string()

def get_sig():
    key = bytes(secret, "utf-8")
    msg = get_string_to_hash().encode("utf-8")
    return hmac.new(key=key, msg=msg, digestmod='sha256').hexdigest().upper()

print(get_sig())

# todo fix up the issues w/encoding, bytes, etc.
#   will need to sort the "headers", which I think are the required query params for a given endpoint
#   figure out which of the items that goes into the has needs to be a member of the client class/object