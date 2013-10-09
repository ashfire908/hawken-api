# -*- coding: utf-8 -*-
# API Exceptions

class ApiException(Exception):
    def __init__(self, message, code):
        self.message = message
        self.code = code
        super(ApiException, self).__init__(message)


class NotAuthorized(ApiException):
    pass


class InternalServerError(ApiException):
    pass


class BackendOverCapacity(ApiException):
    pass


class WrongOwner(ApiException):
    pass
