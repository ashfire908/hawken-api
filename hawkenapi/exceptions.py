# -*- coding: utf-8 -*-
# API exceptions
# Copyright (c) 2013-2014 Andrew Hampe

import re
from enum import Enum


class ApiException(Exception):
    def __init__(self, message, code):
        self.message = message
        self.code = code
        super(ApiException, self).__init__(message)

    def __str__(self):
        return "Status {0}: {1}".format(self.code, self.message)


class AuthenticationFailure(ApiException):
    _re_bad_pass = re.compile(r"^Access Grant Not Issued: Password Incorrect$")

    @property
    def badpass(self):
        return AuthenticationFailure.is_badpass(self.message)

    @staticmethod
    def is_badpass(message):
        return AuthenticationFailure._re_bad_pass.match(message) is not None


class AccountLockout(ApiException):
    _re_lockout_start = re.compile(r"^User locked out for ([0-9]+) minutes\.$")
    _re_lockout_active = re.compile(r"^([0-9]+) until end of account lockout\.$")

    def __init__(self, message, code, attempts):
        super(AccountLockout, self).__init__(message, code)

        match = AccountLockout._re_lockout_start.match(message)
        if match is None:
            match = AccountLockout._re_lockout_active.match(message)
        if match is None:
            raise ValueError("Message cannot be matched")

        self.duration = int(match.group(1))
        self.attempts = int(attempts)

    @staticmethod
    def is_lockout(message):
        return AccountLockout._re_lockout_start.match(message) is not None or AccountLockout._re_lockout_active.match(message) is not None


class AccountBanned(ApiException):
    def __init__(self, message, code, result):
        super(AccountBanned, self).__init__(message, code)

        self.reason = result


class AccountDeactivated(ApiException):
    pass


class NotAuthenticated(ApiException):
    _re_missing = re.compile(r"^Invalid Access Grant$")

    @property
    def missing(self):
        return NotAuthenticated.is_missing(self.message)

    @staticmethod
    def is_missing(message):
        return NotAuthenticated._re_missing.match(message) is not None


class NotAuthorized(ApiException):
    _re_expired = re.compile(r"^Invalid Access Grant:\s*\(exp\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z\) <= now\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z\)\)$")
    _re_revoked = re.compile(r"^Invalid Access Grant:\s+\(Access grant has been revoked\)$")

    @property
    def expired(self):
        return NotAuthorized.is_expired(self.message)

    @property
    def revoked(self):
        return NotAuthorized.is_revoked(self.message)

    @staticmethod
    def is_expired(message):
        return NotAuthorized._re_expired.match(message) is not None

    @staticmethod
    def is_revoked(message):
        return NotAuthorized._re_revoked.match(message) is not None


class NotAllowed(ApiException):
    _re_denied = re.compile(r"^Invalid Access Grant:\s+\(\)$")

    @property
    def denied(self):
        return NotAllowed.is_denied(self.message)

    @staticmethod
    def is_denied(message):
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
    def __init__(self, message, code, result):
        self.result = result
        super(InvalidResponse, self).__init__(message, code)

    def __str__(self):
        return self.message


class InvalidBatch(ApiException):
    def __init__(self, message, code, result):
        self.result = result
        super(InvalidBatch, self).__init__(message, code)

    @property
    def errors(self):
        errors = {}
        if self.result is not None:
            for error in self.result:
                try:
                    errors[error["Error"]].append(error["Guid"])
                except KeyError:
                    errors[error["Error"]] = [error["Guid"]]

        return errors


class InsufficientFunds(ApiException):
    _re_parse = re.compile(r"^Insufficient ([HM]P) funds\.\s+Cost ([0-9]+)\s*:\s*Balance ([0-9]+)$")

    def __init__(self, message, code):
        super(InsufficientFunds, self).__init__(message, code)

        # Parse out the metadata
        self._match = InsufficientFunds._re_parse.match(message)
        if self._match is None:
            self.currency = None
            self.cost = None
            self.balance = None
        else:
            self.currency = self._match.group(1)
            self.cost = int(self._match.group(2))
            self.balance = int(self._match.group(3))

    @property
    def is_match(self):
        return self._match is not None


class InvalidStatTransfer(ApiException):
    _re_notenough = re.compile(r"^Item ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}) does not have enough ([A-Za-z0-9]+) to transfer\.\s+Actual: ([0-9]+) Required ([0-9]+)$")
    _re_toomany = re.compile(r"^Item ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}) has too many ([A-Za-z0-9]+) to transfer\.\s+Proposed: ([0-9]+) Cap: ([0-9]+)$")
    _re_notamultiple = re.compile(r"^Transfer must be a multiple of StatPerCurrency$")
    _re_insufficient = re.compile(r"^User does not have enough ([A-Za-z0-9]+)$")

    class Error(Enum):
        none = 0
        notenough = 1
        toomany = 2
        notamultiple = 3
        insufficient = 4

    def __init__(self, message, code):
        super(InvalidStatTransfer, self).__init__(message, code)

        self.type = InvalidStatTransfer.Error.none
        self.item = None
        self.stat = None
        self.requested = None
        self.threshold = None

        # Parse out the metadata
        match = InvalidStatTransfer._re_notenough.match(message)
        if match:
            self.type = InvalidStatTransfer.Error.notenough
            self.item = match.group(1)
            self.stat = match.group(2)
            self.requested = int(match.group(3))
            self.threshold = int(match.group(4))
        else:
            match = InvalidStatTransfer._re_toomany.match(message)
            if match:
                self.type = InvalidStatTransfer.Error.toomany
                self.item = match.group(1)
                self.stat = match.group(2)
                self.requested = int(match.group(3))
                self.threshold = int(match.group(4))
            else:
                match = InvalidStatTransfer._re_notamultiple.match(message)
                if match:
                    self.type = InvalidStatTransfer.Error.notamultiple
                else:
                    match = InvalidStatTransfer._re_insufficient.match(message)
                    if match:
                        self.type = InvalidStatTransfer.Error.insufficient
                        self.stat = match.group(1)

    @property
    def is_match(self):
        return self.type != InvalidStatTransfer.Error.none
