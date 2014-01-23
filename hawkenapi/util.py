# -*- coding: utf-8 -*-
# Utilities

import base64
import json
from datetime import datetime


def enum(**enums):
    return type('Enum', (), enums)


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
            yield element + '=' * ((4 - len(element) % 4) % 4)
 
    @staticmethod
    def parse_timestamp(s):
        return datetime.strptime(s, "%a, %d %b %Y %H:%M:%S %Z")
