# -*- coding: utf-8 -*-
# Hawken API interface

import logging
import urllib.request
import gzip
import json
from hawkenapi.exceptions import AuthenticationFailure, NotAuthenticated, NotAuthorized, InternalServerError, \
    BackendOverCapacity, WrongOwner, InvalidBatch, auth_exception
from hawkenapi.util import enum
from hawkenapi import endpoints

# Setup logging
logging = logging.getLogger("hawkenapi")


# Request flags
RequestFlags = enum(BATCH="batch")


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
                logging.error("Exception at response - {0} {1}".format(request.method, connection.url))
            except:
                logging.error("Exception at request - {0} {1}".format(request.method, request.selector))
            raise

        # Decode the response
        if content_encoding is None:
            pass
        elif content_encoding == "gzip":
            response = gzip.decompress(response)
        else:
            raise NotImplementedError("Unknown encoding type given")

        # Get flags
        flags = []
        if request.has_header("X-Meteor-Batch"):
            flags.append(RequestFlags.BATCH)

        return (json.loads(response.decode(charset)), {"url": connection.url, "method": request.method, "flags": flags})

    def _get(self, endpoint, auth=None, batch=None):
        request = urllib.request.Request(self._build_endpoint(endpoint), method=endpoints.Methods.GET)
        if batch:
            request.add_header("X-Meteor-Batch", ",".join(batch))

        return self._handle_request(request, auth)

    def _post(self, endpoint, auth=None, data=False):
        if data is False:
            body = None
        elif data is None:
            body = "".encode()
        else:
            body = json.dumps(data).encode()

        request = urllib.request.Request(self._build_endpoint(endpoint), body, method=endpoints.Methods.POST)
        request.add_header("Content-Type", "application/json")

        return self._handle_request(request, auth)

    def _put(self, endpoint, auth=None, data=False):
        if data is False:
            body = None
        elif data is None:
            body = "".encode()
        else:
            body = json.dumps(data).encode()

        request = urllib.request.Request(self._build_endpoint(endpoint), body, method=endpoints.Methods.PUT)
        request.add_header("Content-Type", "application/json")

        return self._handle_request(request, auth)

    def _delete(self, endpoint, auth=None, data=False):
        if data is False:
            body = None
        elif data is None:
            body = "".encode()
        else:
            body = json.dumps(data).encode()

        request = urllib.request.Request(self._build_endpoint(endpoint), body, method=endpoints.Methods.DELETE)
        request.add_header("Content-Type", "application/json")

        return self._handle_request(request, auth)

    def _check_response(self, response, check_request=True):
        # Log the request
        logging.debug("{0[method]} {0[url]} {1}".format(response[1], response[0]["Status"]))

        # Check for general errors
        if response[0]["Status"] == 503:
            raise BackendOverCapacity(response[0]["Message"], response[0]["Status"])
        if response[0]["Status"] == 500:
            raise InternalServerError(response[0]["Message"], response[0]["Status"])
        if check_request:
            # Check for request errors
            if response[0]["Status"] == 401:
                auth_exception(response[0])
            elif response[0]["Status"] == 400 and RequestFlags.BATCH in response[1]["flags"]:
                raise InvalidBatch(response[0]["Message"], response[0]["Status"], response[0]["Result"])

        # Return the response data
        return response[0]

    def _no_auth(self, api_call, check_request=True):
        response = self._check_response(api_call(), check_request)

        return response

    def _require_auth(self, api_call, check_request=True):
        if self.grant is None:
            if self._auto_auth:
                logging.info("Automatically authenticating.")
                self.auth(self.auth_username, self.auth_password)
            else:
                logging.error("Auth-required request made but no auth performed or credentials given.")
                raise NotAuthenticated("Auth-required request made but no auth performed or credentials given", 401)

        try:
            response = self._check_response(api_call(), check_request)
        except NotAuthorized as ex:
            # Only reauth if the auth was expired
            if ex.expired and self._auto_auth:
                logging.info("Automatically authenticating [reauth] ({0})".format(response["Message"]))
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
        endpoint = endpoints.user_accessgrant.format(username)
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

    def deauth(self, guid, access_token=None):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        # Check for if a custom token was passed
        if access_token is None:
            access_token = self.grant
        # Check that we don't have a blank access token
        elif not isinstance(access_token, str) or access_token == "":
            raise ValueError("Access Token cannot be blank")

        # Get the request together
        endpoint = endpoints.user_accessgrant.format(guid)
        data = {"AccessGrant": access_token}

        response = self._require_auth((lambda: self._put(endpoint, access_token, data=data)))

        if response["Status"] == 200:
            return True
        else:
            return False

    def auto_auth(self, username, password):
        self.auth_username = username
        self.auth_password = password
        self._auto_auth = True

    def user_account(self, identifier):
        # Check that we don't have a blank identifier
        if not isinstance(identifier, str) or identifier == "":
            raise ValueError("Identifier cannot be blank")

        endpoint = endpoints.user.format(identifier)

        try:
            response = self._require_auth(lambda: self._get(endpoint, self.grant))
        except NotAuthorized as ex:
            if not ex.expired:
                raise WrongOwner(ex.message, ex.code)
            else:
                raise

        return response["Result"]

    def user_publicdata(self, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.user_publicdata_single.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def user_callsign(self, guid):
        response = self.user_publicdata(guid)

        # Some users don't have a callsign
        if response is not None:
            try:
                return response["UniqueCaseInsensitive_Callsign"]
            except KeyError:
                # Catch it in the following line
                pass

        return None

    def user_guid(self, callsign):
        # Check that we don't have a blank callsign
        if not isinstance(callsign, str) or callsign == "":
            raise ValueError("Callsign cannot be blank")

        endpoint = endpoints.uniquevalues_callsign.format(callsign)

        response = self._no_auth(lambda: self._get(endpoint))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]["UserGuid"]

    def user_server(self, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.server_user.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def user_stats(self, guid):
        if isinstance(guid, str):
            # Single request
            if guid == "":
                raise ValueError("User GUID cannot be blank")

            endpoint = endpoints.user_stat_single.format(guid)
            response = self._require_auth(lambda: self._get(endpoint, self.grant))
        else:
            # Batch request
            if len(guid) == 0:
                raise ValueError("List of user GUIDs cannot be empty")

            endpoint = endpoints.user_stat_batch.format()
            response = self._require_auth(lambda: self._get(endpoint, self.grant, batch=guid))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def server_list(self, guid=None):
        if guid is None:
            endpoint = endpoints.server.format()
        else:
            # Check that we don't have a blank guid
            if not isinstance(guid, str) or guid == "":
                raise ValueError("Server GUID cannot be blank")

            endpoint = endpoints.server_single.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def server_by_name(self, name):
        server_list = self.server_list()

        found_server = None
        name = name.lower()
        for server in server_list:
            if server["ServerName"].lower() == name:
                found_server = server
                break

        return found_server

    def matchmaking_advertisement(self, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("Advertisement GUID cannot be blank")
        endpoint = endpoints.advertisement_single.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def matchmaking_advertisement_post(self, advertisement):
        endpoint = endpoints.advertisement.format()

        response = self._require_auth(lambda: self._post(endpoint, self.grant, advertisement))

        if response["Status"] == 403:
            raise WrongOwner(response["Message"], response["Status"])

        return response["Result"]

    def matchmaking_advertisement_post_matchmaking(self, gameversion, gametype, region, owner, users, party=None):
        # Check the parameters given
        if not isinstance(gameversion, str) or gameversion == "":
            raise ValueError("Game Version cannot be blank")
        if not isinstance(gametype, str) or gametype == "":
            raise ValueError("Game Type cannot be blank")
        if not isinstance(region, str) or region == "":
            raise ValueError("Region cannot be blank")
        if not isinstance(owner, str) or owner == "":
            raise ValueError("Owner cannot be blank")
        if len(users) == 0:
            raise ValueError("Users list cannot be empty")

        advertisement = {
            "GameType": gametype,
            "GameVersion": gameversion,
            "OwnerGuid": owner,
            "Region": region,
            "Users": users
        }

        if party is not None:
            if not isinstance(party, str) or party == "":
                raise ValueError("Party GUID cannot be blank")
            advertisement["PartyGuid"] = party

        return self.matchmaking_advertisement_post(advertisement)

    def matchmaking_advertisement_post_server(self, gameversion, region, server, owner, users, party=None):
        # Check the parameters given
        if not isinstance(gameversion, str) or gameversion == "":
            raise ValueError("Game Version cannot be blank")
        if not isinstance(region, str) or region == "":
            raise ValueError("Region cannot be blank")
        if not isinstance(server, str) or server == "":
            raise ValueError("Server cannot be blank")
        if not isinstance(owner, str) or owner == "":
            raise ValueError("Owner cannot be blank")
        if len(users) == 0:
            raise ValueError("Users list cannot be empty")

        advertisement = {
            "GameVersion": gameversion,
            "OwnerGuid": owner,
            "Region": region,
            "RequestedServerGuid": server,
            "Users": users
        }

        if party is not None:
            if not isinstance(party, str) or party == "":
                raise ValueError("Party GUID cannot be blank")
            advertisement["PartyGuid"] = party

        return self.matchmaking_advertisement_post(advertisement)

    def matchmaking_advertisement_delete(self, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("Advertisement GUID cannot be blank")
        endpoint = endpoints.advertisement_single.format(guid)

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
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")
        endpoint = endpoints.presence_access.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        return response["Result"]

    def presence_domain(self, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")
        endpoint = endpoints.presence_domain.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        return response["Result"]

    def game_items(self, guid=None):
        if guid is None:
            endpoint = endpoints.item.format()
        else:
            if not isinstance(guid, str) or guid == "":
                raise ValueError("Item GUID cannot be blank")
            endpoint = endpoints.item_single.format(guid)

        response = self._require_auth(lambda: self._get(endpoint, self.grant))

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]
