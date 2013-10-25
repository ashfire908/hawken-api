# -*- coding: utf-8 -*-
# API Exceptions

import re


class ApiException(Exception):
    def __init__(self, message, code):
        self.message = message
        self.code = code
        super(ApiException, self).__init__(message)


class NotAuthorized(ApiException):
    _re_expired = re.compile(r"Invalid Access Grant:\s*\(exp\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z\) <= now\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{7}Z\)\)")

    def __getattr__(self, key):
        if key == "expired":
            return self._expired()
        else:
            raise AttributeError

    def _expired(self):
        return self._re_expired.match(self.message) is not None


class InternalServerError(ApiException):
    pass


class BackendOverCapacity(ApiException):
    pass


class WrongOwner(ApiException):
    pass
