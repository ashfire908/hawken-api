# -*- coding: utf-8 -*-
# High-level API Client

import time
from datetime import datetime
import logging
from hawkenapi.interface import Interface
from hawkenapi.exceptions import NotAuthenticated, NotAuthorized, InternalServerError, ServiceUnavailable, \
    RequestError, RetryLimitExceeded
from hawkenapi.util import JWTParser

# Setup logging
logger = logging.getLogger(__name__)


# Decorators
def require_auth(f):
    def auth_handler(self, *args, **kwargs):
        # Check if we have authenticated
        if not self.authed:
            logger.error("Auth-required request made but no authentication has been performed.")
            raise NotAuthenticated("Client has not authenticated to the API", 401)
        # Check if the grant has expired
        elif self.grant.is_expired:
            logger.info("Automatically authenticating [expired]")
            self._reauth()

        try:
            response = f(self, *args, **kwargs)
        except NotAuthorized as e:
            # Only reauth if the grant expired
            if e.expired:
                logger.info("Automatically authenticating [reauth] ([{0}] {1})".format(e.code, e.message))
                self._reauth()
                response = f(self, *args, **kwargs)
            else:
                raise

        return response
    return auth_handler


# Access grant
class AccessGrant:
    def __init__(self, token):
        self.token = token

        # Parse the token
        jwt = JWTParser(self.token)

        # Set data
        self.id = jwt.payload["jti"]
        self.user = jwt.payload["prn"]
        self.expires = jwt.payload["exp"]
        self.not_before = jwt.payload["nbf"]

    @property
    def is_expired(self):
        return datetime.now() > self.expires

    def __str__(self):
        return self.token


# Client
class Client:
    def __init__(self, retry_attempts=1, retry_delay=1, **kwargs):
        self._interface = Interface(**kwargs)

        # Init auth data
        self.grant = None
        self.guid = None
        self._username = None
        self._password = None

        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

    def _wrapper(self, method, *args, **kwargs):
        last_exception = None
        i = 0
        success = False
        response = None
        while self.retry_attempts > i:
            try:
                response = method(*args, **kwargs)
            except (InternalServerError, ServiceUnavailable, RequestError) as e:
                logger.warning("Temporary error returned, automatically retrying... (Attempt {0} of {1})".format(i + 1, self.retry_attempts))
                last_exception = e
                if self.retry_attempts >= i:
                    time.sleep(self.retry_delay)
            else:
                success = True
                break

            i += 1

        if success:
            return response
        else:
            raise RetryLimitExceeded(i, last_exception) from last_exception

    def _reauth(self):
        return self.login(self._username, self._password)

    @property
    def authed(self):
        return self.grant is not None

    def login(self, username, password):
        # Auth to the API
        grant = self._wrapper(self._interface.auth, username, password)

        if grant:
            # Save the user/password
            self._username = username
            self._password = password

            # Load in the grant info
            self.grant = AccessGrant(grant)
            self.guid = self.grant.user

            return True
        return False

    @require_auth
    def logout(self):
        try:
            result = self._wrapper(self._interface.deauth, str(self.grant), self.guid)
        finally:
            # Reset the auth info
            self.grant = None
            self.guid = None
            self._username = None
            self._password = None

        return result

    @require_auth
    def get_user(self, identifier):
        return self._wrapper(self._interface.user_account, self.grant, identifier)

    def get_user_guid(self, callsign):
        return self._wrapper(self._interface.user_guid, callsign)

    @require_auth
    def get_user_callsign(self, guid):
        response = self._wrapper(self._interface.user_publicdata, self.grant, guid)

        # Some users don't have a callsign
        if response is not None:
            try:
                return response["UniqueCaseInsensitive_Callsign"]
            except KeyError:
                # Catch it in the following line
                pass

        return None

    @require_auth
    def get_user_server(self, guid):
        return self._wrapper(self._interface.user_server, self.grant, guid)

    @require_auth
    def get_user_stats(self, guid):
        if isinstance(guid, str):
            return self._wrapper(self._interface.user_stats_single, self.grant, guid)
        else:
            return self._wrapper(self._interface.user_stats_batch, self.grant, guid)

    @require_auth
    def get_server(self, guid=None):
        if guid is None:
            return self._wrapper(self._interface.server_list, self.grant)
        else:
            return self._wrapper(self._interface.server_single, self.grant, guid)

    @require_auth
    def get_server_by_name(self, name):
        server_list = self._wrapper(self._interface.server_list, self.grant)

        servers = []
        name = name.lower()
        for server in server_list:
            if server["ServerName"].lower() == name:
                servers.append(server)

        return servers

    @require_auth
    def get_advertisement(self, guid):
        return self._wrapper(self._interface.matchmaking_advertisement, self.grant, guid)

    @require_auth
    def post_matchmaking_advertisement(self, gameversion, region, users, gametype=None, party=None):
        advertisement = self._interface.generate_advertisement_matchmaking(gameversion, region, self.guid, users, gametype, party)

        return self._wrapper(self._interface.matchmaking_advertisement_post, self.grant, advertisement)

    @require_auth
    def post_server_advertisement(self, gameversion, region, server, users, party=None):
        advertisement = self._interface.generate_advertisement_server(gameversion, region, server, self.guid, users, party)

        return self._wrapper(self._interface.matchmaking_advertisement_post, self.grant, advertisement)

    @require_auth
    def delete_advertisement(self, guid):
        return self._wrapper(self._interface.matchmaking_advertisement_delete, self.grant, guid)

    @require_auth
    def get_presence_access(self):
        return self._wrapper(self._interface.presence_access, self.grant, self.guid)

    @require_auth
    def get_presence_domain(self):
        return self._wrapper(self._interface.presence_domain, self.grant, self.guid)

    @require_auth
    def get_game_items(self, guid=None):
        if guid is None:
            return self._wrapper(self._interface.game_items, self.grant)
        else:
            return self._wrapper(self._interface.game_items_single, self.grant, guid)
