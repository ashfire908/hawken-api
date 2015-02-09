# -*- coding: utf-8 -*-
# Utilities
# Copyright (c) 2013-2015 Andrew Hampe

import re
import base64
import json
from datetime import datetime


def chunks(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


def verify_guid(guid):
    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", guid) is None:
        return False

    return True


def verify_match(match):
    if re.match(r"^[0-9a-fA-F]{8}4[0-9a-fA-F]{23}$", match) is None:
        return False

    return True


def create_flags(*flags):
    class Flags:
        def __init__(self, *args):
            for flag in flags:
                setattr(self, flag, False)

            for flag in args:
                if flag not in flags:
                    raise ValueError("Invalid flag")

                setattr(self, flag, True)

    return Flags


class JWTParser:
    """JSON Web Token (JWT) Parser

    Takes a JWT and parses it into it's components.

    Based off of Shadeness' Simple JWT Parser: https://gist.github.com/Zren/f6d3fe8c7c7220d80625"""

    def __init__(self, token):
        # Split token and pad elements
        header, payload, signature = self.pad(token.split("."))

        # Decode elements
        self.header = json.loads(base64.urlsafe_b64decode(header).decode())
        self.payload = json.loads(base64.urlsafe_b64decode(payload).decode())
        self.signature = base64.urlsafe_b64decode(signature)

        # Convert timestamps to python data types
        for key in ("exp", "nbf", "iat"):
            if key in self.payload:
                self.payload[key] = self.parse_timestamp(self.payload[key])

    @staticmethod
    def pad(elements):
        for element in elements:
            yield element + "=" * ((4 - len(element) % 4) % 4)

    @staticmethod
    def parse_timestamp(timestamp):
        return datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S %Z")


def copyappend(seq, item):
    seq_list = list(seq)
    seq_list.append(item)
    return seq_list
