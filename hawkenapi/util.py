# -*- coding: utf-8 -*-
# Utilities

import re
import base64
import json
import ctypes
from datetime import datetime


def enum(**enums):
    return type("Enum", (), enums)


def chunks(l, n):
    return [l[i:i + n] for i in range(0, len(l), n)]


def verify_guid(guid):
    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", guid) is None:
        return False

    return True


def create_bitfield(*fields):
    field_list = []
    for field in fields:
        field_list.append((field, ctypes.c_uint8, 1))

    class Bits(ctypes.LittleEndianStructure):
        _fields_ = field_list

        def __init__(self, bits=None):
            super().__init__()

            if bits is not None:
                for bit in list(bits):
                    setattr(self, bit, 1)

    return Bits


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
    def parse_timestamp(s):
        return datetime.strptime(s, "%a, %d %b %Y %H:%M:%S %Z")
