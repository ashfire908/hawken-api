# -*- coding: utf-8 -*-
# API exceptions
# Copyright (c) 2013-2015 Andrew Hampe

import re
import requests
from enum import Enum, unique
from hawkenapi.mappings import CurrencyType
from hawkenapi.util import parse_datetime


class ApiException(Exception):
    def __init__(self, response):
        self.response = response

        # Detect exception type
        if self.response.status_code != requests.codes.ok:
            self.status = self.response.status_code
            self.message = self.response.reason
        else:
            body = self.response.json()

            self.status = int(body["Status"])
            self.message = body["Message"]

        super().__init__("[{0}] {1}".format(self.status, self.message))


class AuthenticationFailure(ApiException):
    pass


class AccountLockout(ApiException):
    _re_lockout_start = re.compile(r"^User locked out for ([0-9]+) minutes\.$")
    _re_lockout_active = re.compile(r"^([0-9]+) until end of account lockout\.$")

    def __init__(self, response):
        super().__init__(response)

        match = AccountLockout._re_lockout_start.match(self.message)
        if match is None:
            match = AccountLockout._re_lockout_active.match(self.message)
        if match is None:
            raise ValueError("Message cannot be matched")

        self.remaining_minutes = int(match.group(1))
        self.attempts = int(self.response.json()["Result"])

    @staticmethod
    def detect(response):
        message = response.json()["Message"]
        return AccountLockout._re_lockout_start.match(message) is not None or AccountLockout._re_lockout_active.match(message) is not None


class AccountBanned(ApiException):
    def __init__(self, response):
        super().__init__(response)

        self.reason = self.response.json()["Result"]


class AccountDeactivated(ApiException):
    _str_deactivated = "User deactivated"

    @staticmethod
    def detect(response):
        message = response.json()["Message"]
        return message == AccountDeactivated._str_deactivated


class NotAuthenticated(ApiException):
    _str_missing = "Invalid Access Grant"

    @staticmethod
    def detect(response):
        message = response.json()["Message"]
        return message == NotAuthenticated._str_missing


class NotAuthorized(ApiException):
    _re_not_yet = re.compile(r"^Invalid Access Grant:\s*\(nbf\(([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z)\) >= now\(([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z)\)\)$")
    _re_expired = re.compile(r"^Invalid Access Grant:\s*\(exp\(([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z)\) <= now\(([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z)\)\)$")
    _re_revoked = re.compile(r"^Invalid Access Grant:\s+\(Access grant has been revoked\)$")

    @unique
    class Error(Enum):
        invalid = 0
        expired = 1
        revoked = 2
        not_yet = 3

    def __init__(self, response):
        super().__init__(response)

        self.not_before = None
        self.expires = None
        self.now = None

        match = NotAuthorized._re_not_yet.match(self.message)
        if match is not None:
            self.error = NotAuthorized.Error.not_yet
            self.not_before = parse_datetime(match.group(1))
            self.now = parse_datetime(match.group(2))
        else:
            match = NotAuthorized._re_expired.match(self.message)
            if match is not None:
                self.error = NotAuthorized.Error.expired
                self.expires = parse_datetime(match.group(1))
                self.now = parse_datetime(match.group(2))
            elif NotAuthorized._re_revoked.match(self.message) is not None:
                self.error = NotAuthorized.Error.revoked
            else:
                self.error = NotAuthorized.Error.invalid

    @staticmethod
    def detect(response):
        message = response.json()["Message"]
        regexs = (NotAuthorized._re_not_yet, NotAuthorized._re_expired, NotAuthorized._re_revoked)
        return any((regex.match(message) is not None for regex in regexs))


class NotAllowed(ApiException):
    _re_denied = re.compile(r"^Invalid Access Grant:\s+\(\)$")

    @staticmethod
    def detect(response):
        message = response.json()["Message"]
        return NotAllowed._re_denied.match(message) is not None


class InternalServerError(ApiException):
    pass


class ServiceUnavailable(ApiException):
    pass


class WrongUser(ApiException):
    pass


class InvalidRequest(ApiException):
    pass


class InvalidResponse(ApiException):
    def __init__(self, response, issue):
        super().__init__(response)
        self.issue = issue

    def __str__(self):
        return self.issue


class InvalidBatch(ApiException):
    def __init__(self, response):
        super().__init__(response)
        body = self.response.json()

        self.errors = {}
        if "Result" in body:
            for error in body["Result"]:
                try:
                    self.errors[error["Error"]].append(error["Guid"])
                except KeyError:
                    self.errors[error["Error"]] = [error["Guid"]]

    @staticmethod
    def detect(response):
        if "X-Meteor-Batch" in response.request.headers:
            message = response.json()["Message"]
            if message in ("Batch request must contain valid guids in 'x-meteor-batch'.", "Invalid users ID"):
                return True

        return False


class InsufficientFunds(ApiException):
    _re_parse = re.compile(r"^Insufficient ([HM]P) funds\.\s+Cost ([0-9]+)\s*:\s*Balance ([0-9]+)$")

    def __init__(self, response):
        super().__init__(response)

        # Parse out the metadata
        match = InsufficientFunds._re_parse.match(self.message)
        self.currency = CurrencyType(match.group(1))
        self.cost = int(match.group(2))
        self.balance = int(match.group(3))


class InvalidStatTransfer(ApiException):
    _re_notenough = re.compile(r"^Item ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}) does not have enough ([A-Za-z0-9]+) to transfer\.\s+Actual: ([0-9]+) Required ([0-9]+)$")
    _re_toomany = re.compile(r"^Item ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}) has too many ([A-Za-z0-9]+) to transfer\.\s+Proposed: ([0-9]+) Cap: ([0-9]+)$")
    _re_insufficient = re.compile(r"^User does not have enough ([A-Za-z0-9]+)$")
    _str_notamultiple = "Transfer must be a multiple of StatPerCurrency"

    @unique
    class Error(Enum):
        none = 0  # This is a fault
        notenough = 1
        toomany = 2
        notamultiple = 3
        insufficient = 4

    def __init__(self, response):
        super().__init__(response)

        self.type = InvalidStatTransfer.Error.none
        self.item = None
        self.stat = None
        self.requested = None
        self.threshold = None

        # Parse out the metadata
        match = InvalidStatTransfer._re_notenough.match(self.message)
        if match:
            self.type = InvalidStatTransfer.Error.notenough
            self.item = match.group(1)
            self.stat = match.group(2)
            self.requested = int(match.group(3))
            self.threshold = int(match.group(4))
        else:
            match = InvalidStatTransfer._re_toomany.match(self.message)
            if match:
                self.type = InvalidStatTransfer.Error.toomany
                self.item = match.group(1)
                self.stat = match.group(2)
                self.requested = int(match.group(3))
                self.threshold = int(match.group(4))
            else:
                match = InvalidStatTransfer._re_insufficient.match(self.message)
                if match:
                    self.type = InvalidStatTransfer.Error.insufficient
                    self.stat = match.group(1)
                elif self.message == InvalidStatTransfer._str_notamultiple:
                    self.type = InvalidStatTransfer.Error.notamultiple

    @staticmethod
    def detect(response):
        message = response.json()["Message"]
        if InvalidStatTransfer._re_notenough.match(message) is None:
            if InvalidStatTransfer._re_toomany.match(message) is None:
                if InvalidStatTransfer._re_insufficient.match(message) is None:
                    if message != InvalidStatTransfer._str_notamultiple:
                        return False

        return True
