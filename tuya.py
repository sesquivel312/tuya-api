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


print(get_sig())

# todo fix up the issues w/encoding, bytes, etc.
#   will need to sort the "headers", which I think are the required query params for a given endpoint
#   figure out which of the items that goes into the has needs to be a member of the client class/object