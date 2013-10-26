# -*- coding: utf-8 -*-
# Hawken API interface

import logging
import urllib.request
import urllib.parse
import gzip
import json
from hawkenapi.exceptions import AuthenticationFailure, NotAuthenticated, NotAuthorized, InternalServerError, BackendOverCapacity, WrongOwner, auth_exception


class Client:
    def __init__(self, stack="services.live", scheme="http"):
        self.user_agent = ""
        self.stack = stack
        self.scheme = scheme
        self.grant = None
        self._auto_auth = False

    def _build_endpoint(self, endpoint):
        return "{0}://{1}.hawken.meteor-ent.com/{2}".format(self.scheme, self.stack, endpoint)

    def _handle_request(self, request, auth):
        # Add global headers
        request.add_header("User-Agent", self.user_agent)
        request.add_header("Accept-Encoding", "gzip")

        # Handle auth
        if auth is not None:
            request.add_header("Authorization", "Basic %s" % auth)

        try:
            # Open the connection, load the data
            connection = urllib.request.urlopen(request)
            try:
                response = connection.read()

                # Grab the info we need
                charset = connection.info().get_content_charset("utf-8")  # Fallback: UTF-8
                content_encoding = connection.getheader("Content-Encoding")

            finally:
                # Close the connection
                connection.close()
        except:
            try:
                logging.error("API: Exception at response - {0} {1}".format(request.method, connection.url))
            except:
                logging.error("API: Exception at request - {0} {1}".format(request.method, request.selector))
            raise

        # Decode the response
        if content_encoding is None:
            pass
        elif content_encoding == "gzip":
            response = gzip.decompress(response)
        else:
            raise NotImplementedError("Unknown encoding type given.")

        return (json.loads(response.decode(charset)), {"url": connection.url, "method": request.method})

    def _get(self, endpoint, auth=None):
        request = urllib.request.Request(self._build_endpoint(endpoint), method="GET")

        return self._handle_request(request, auth)

    def _post(self, endpoint, auth=None, data=False):
        if data is False:
            body = None
        elif data is None:
            body = "".encode()
        else:
            body = json.dumps(data).encode()

        request = urllib.request.Request(self._build_endpoint(endpoint), body, method="POST")
        request.add_header("Content-Type", "application/json")

        return self._handle_request(request, auth)

    def _delete(self, endpoint, auth=None, data=False):
        if data is False:
            body = None
        elif data is None:
            body = "".encode()
        else:
            body = json.dumps(data).encode()

        request = urllib.request.Request(self._build_endpoint(endpoint), body, method="DELETE")
        request.add_header("Content-Type", "application/json")

        return self._handle_request(request, auth)

    def _check_response(self, response, check_request=True):
        # Log the request
        logging.debug("API: {0[method]} {0[url]} {1}".format(response[1], response[0]["Status"]))

        # Check for general errors
        if response[0]["Status"] == 503:
            raise BackendOverCapacity(response["Message"], response["Status"])
        if response[0]["Status"] == 500:
            raise InternalServerError(response["Message"], response["Status"])
        if check_request:
            # Check for request errors
            if response[0]["Status"] == 401:
                auth_exception(response[0])

        # Return the response data
        return response[0]

    def _no_auth(self, api_call, check_request=True):
        response = self._check_response(api_call(), check_request)

        return response

    def _require_auth(self, api_call, check_request=True):
        if self.grant is None:
            if self._auto_auth:
                logging.info("API: Automatically authenticating.")
                self.auth(self.auth_username, self.auth_password)
            else:
                logging.error("API: Auth-required request made but no auth performed or credentials given.")
                raise NotAuthenticated("Auth-required request made but no auth performed or credentials given.", 401)

        try:
            response = self._check_response(api_call(), check_request)
        except NotAuthorized as ex:
            # Only reauth if the auth was expired
            if ex.expired and self._auto_auth:
                logging.info("API: Automatically authenticating [reauth] ({0})".format(response["Message"]))
                self.auth(self.auth_username, self.auth_password)
                response = self._check_response(api_call(), check_request)
            else:
                raise

        return response

    def auth(self, username, password):
        # Check that we don't have a blank username/password
        if not isinstance(username, str) or username == "":
            raise ValueError("Username cannot be blank")
        if not isinstance(password, str) or password == "":
            raise ValueError("Password cannot be blank")

        # Get the request together
        endpoint = "users/{0}/accessGrant".format(urllib.parse.quote(username))
        data = {"Password": password}

        response = self._no_auth((lambda: self._post(endpoint, data=data)), check_request=False)

        if response["Status"] == 200:
            self.grant = response["Result"]
            return True
        elif response["Status"] == 401 or response["Status"] == 404 or response["Status"] == 400:
            # No such user/Bad password/Blank password
            raise AuthenticationFailure(response["Message"], response["Status"])
        else:
            return False

    def auto_auth(self, username, password):
        self.auth_username = username
        self.auth_password = password
        self._auto_auth = True

    def user_callsign(self, guid):
        endpoint = "userPublicReadOnlyData/{0}".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            # Some users don't have a callsign
            try:
                return response["Result"]["UniqueCaseInsensitive_Callsign"]
            except KeyError:
                return None

    def user_guid(self, callsign):
        endpoint = "uniqueValues/UniqueCaseInsensitive_UserPublicReadOnlyData_Callsign/{0}".format(callsign)

        response = self._no_auth(lambda: self._get(endpoint))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]["UserGuid"]

    def user_server(self, guid):
        endpoint = "userGameServers/{0}".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def user_stats(self, guid):
        endpoint = "userStats/{0}".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def server_list(self):
        endpoint = "gameServerListings"

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        return response["Result"]

    def server_info(self, guid):
        endpoint = "gameServerListings/{0}".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def server_info_by_name(self, name):
        server_list = self.server_list()

        found_server = None
        name = name.lower()
        for server in server_list:
            if server["ServerName"].lower() == name:
                found_server = server
                break

        return found_server

    def matchmaking_advertisement(self, guid):
        endpoint = "hawkenClientMatchmakingAdvertisements/{0}".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def matchmaking_advertisement_post(self, gameversion, gametype, region, owner, users, party=None):
        endpoint = "hawkenClientMatchmakingAdvertisements"
        advertisement = {
            "GameType": gametype,
            "GameVersion": gameversion,
            "OwnerGuid": owner,
            "Region": region,
            "Users": users
        }

        if party is not None:
            advertisement["PartyGuid"] = party

        response = self._require_auth(lambda: self._post(endpoint, self.grant, advertisement))

        if response["Status"] == 403:
            raise WrongOwner(response["Message"], response["Status"])

        return response["Result"]

    def matchmaking_advertisement_post_server(self, gameversion, region, server, owner, users, party=None):
        endpoint = "hawkenClientMatchmakingAdvertisements"
        advertisement = {
            "GameVersion": gameversion,
            "OwnerGuid": owner,
            "Region": region,
            "RequestedServerGuid": server,
            "Users": users
        }

        if party is not None:
            advertisement["PartyGuid"] = party

        response = self._require_auth(lambda: self._post(endpoint, self.grant, advertisement))

        if response["Status"] == 403:
            raise WrongOwner(response["Message"], response["Status"])

        return response["Result"]

    def matchmaking_advertisement_delete(self, guid):
        endpoint = "hawkenClientMatchmakingAdvertisements/{0}".format(guid)

        response = self._require_auth(lambda: self._delete(endpoint, self.grant))

        if response["Status"] == 403:
            raise WrongOwner(response["Message"], response["Status"])
        if response["Status"] == 404:
            return None
        elif response["Status"] == 200:
            return True
        else:
            return False

    def presence_access(self, guid):
        endpoint = "thirdParty/{0}/Presence/Access".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        return response["Result"]

    def presence_domain(self, guid):
        endpoint = "thirdParty/{0}/Presence/Domain".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        return response["Result"]

    def game_items(self, guid=None):
        if guid is None:
            endpoint = "gameItems"
        else:
            endpoint = "gameItems/{0}".format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]
