# -*- coding: utf-8 -*-
# API Exceptions

import re


class ApiException(Exception):
    def __init__(self, message, code):
        self.message = message
        self.code = code
        super(ApiException, self).__init__(message)


class AuthenticationFailure(ApiException):
    _re_bad_pass = re.compile(r"^Access Grant Not Issued: Password Incorrect$")

    def __getattr__(self, key):
        if key == "badpass":
            return self.is_badpass(self.message)
        else:
            raise AttributeError

    @staticmethod
    def is_badpass(message):
        return AuthenticationFailure._re_bad_pass.match(message) is not None


class NotAuthenticated(ApiException):
    _re_missing = re.compile(r"^Invalid Access Grant$")

    def __getattr__(self, key):
        if key == "missing":
            return self.is_missing(self.message)
        else:
            raise AttributeError

    @staticmethod
    def is_missing(message):
        return NotAuthenticated._re_missing.match(message) is not None


class NotAuthorized(ApiException):
    _re_expired = re.compile(r"^Invalid Access Grant:\s*\(exp\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z\) <= now\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z\)\)$")

    def __getattr__(self, key):
        if key == "expired":
            return self.is_expired(self.message)
        else:
            raise AttributeError

    @staticmethod
    def is_expired(message):
        return NotAuthorized._re_expired.match(message) is not None


class InternalServerError(ApiException):
    pass


class BackendOverCapacity(ApiException):
    pass


class WrongOwner(ApiException):
    pass


def auth_exception(response):
    if NotAuthenticated.is_missing(response["Message"]):
        raise NotAuthenticated(response["Message"], response["Status"])
    elif AuthenticationFailure.is_badpass(response["Message"]):
        raise AuthenticationFailure(response["Message"], response["Status"])
    else:
        raise NotAuthorized(response["Message"], response["Status"])
