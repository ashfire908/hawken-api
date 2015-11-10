# -*- coding: utf-8 -*-
# Utilities
# Copyright (c) 2013-2015 Andrew Hampe

import re
import base64
import json
from datetime import datetime
from collections import OrderedDict
from inspect import signature, Parameter

BLANK_GUID = "00000000-0000-0000-0000-000000000000"
GUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
MATCH_REGEX = re.compile(r"^[0-9a-f]{8}4[0-9a-f]{13}[89ab][0-9a-f]{9}$", re.IGNORECASE)


def chunks(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


def verify_guid(guid):
    return GUID_REGEX.match(guid) is not None


def verify_match(match):
    return MATCH_REGEX.match(match) is not None


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


def bind_arguments(func, *args, **kwargs):
    # Manually bind arguments since signature().bind().args/kwargs is broken
    sig = signature(func)
    bound = sig.bind(*args, **kwargs)
    new_args = []
    new_kwargs = OrderedDict()
    for param in sig.parameters.values():
        if param.kind == Parameter.POSITIONAL_ONLY:
            new_args.append(bound.arguments[param.name])
        elif param.kind == Parameter.POSITIONAL_OR_KEYWORD:
            if param.default == Parameter.empty:
                new_args.append(bound.arguments[param.name])
            elif param.name in bound.arguments and bound.arguments[param.name] != param.default:
                new_kwargs[param.name] = bound.arguments[param.name]
        elif param.kind == Parameter.VAR_POSITIONAL:
            if param.name in bound.arguments:
                new_args.extend(bound.arguments[param.name])
        elif param.kind == Parameter.KEYWORD_ONLY:
            if param.name in bound.arguments:
                new_kwargs[param.name] = bound.arguments[param.name]
        # VAR_KEYWORD
        elif param.name in bound.arguments:
            for name, value in bound.arguments[param.name]:
                new_kwargs[name] = value

    return new_args, new_kwargs


def bind_wrapped_arguments(func, *args, **kwargs):
    new_args, new_kwargs = bind_arguments(func, *args, **kwargs)
    return new_args[1:], new_kwargs
