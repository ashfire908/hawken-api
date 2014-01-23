# -*- coding: utf-8 -*-
# Low-level API Interface

import logging
import urllib.request
import urllib.error
import http.client
import gzip
import json
import hawkenapi
from hawkenapi import endpoints
from hawkenapi.exceptions import AuthenticationFailure, NotAuthorized, InternalServerError, \
    ServiceUnavailable, WrongOwner, InvalidRequest, InvalidBatch, auth_exception, RequestError
from hawkenapi.util import enum

# Setup logging
logger = logging.getLogger(__name__)

# Request flags
RequestFlags = enum(BATCH="batch")


# Interface
class Interface:
    def __init__(self, host=None, stack=None, scheme="http"):
        self.user_agent = "HawkenApi/{0}".format(hawkenapi.__version__)
        if host is not None:
            self.host = host
        elif stack is not None:
            self.host = "{0}.hawken.meteor-ent.com".format(stack)
        else:
            self.host = "services.live.hawken.meteor-ent.com"
        self.scheme = scheme

    def _build_endpoint(self, endpoint):
        return "{0}://{1}/{2}".format(self.scheme, self.host, endpoint)

    def _request_prepare(self, endpoint, method, auth=None, data=False, batch=None):
        # Encode data
        if data is False:
            body = None
        elif data is None:
            body = "".encode()
        else:
            body = json.dumps(data).encode()

        request = urllib.request.Request(self._build_endpoint(endpoint), body, method=method)

        # Add headers
        if auth is not None:
            request.add_header("Authorization", "Basic %s" % auth)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if batch:
            request.add_header("X-Meteor-Batch", ",".join(batch))

        return request

    def _request_perform(self, request):
        # Add global headers
        request.add_header("User-Agent", self.user_agent)
        request.add_header("Accept-Encoding", "gzip")

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
                logger.error("Exception at response - {0} {1}".format(request.method, connection.url))
            except:
                logger.error("Exception at request - {0} {1}".format(request.method, request.selector))
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

    def request(self, endpoint, method, check_request=True, **kwargs):
        try:
            # Create the API request
            request = self._request_prepare(endpoint, method, **kwargs)
            # Perform the request
            response = self._request_perform(request)
        except http.client.BadStatusLine as e:
            # Handle bad status error (network error)
            raise RequestError("HTTP Bad Status") from e
        except urllib.error.HTTPError as e:
            # Handle HTTP errors
            if e.code == 503:
                # Service unavailable (usually backend at capacity)
                raise ServiceUnavailable(e.reason, e.code) from e
            elif e.code == 500:
                # Internal server error (HTTP level)
                raise InternalServerError(e.reason, e.code) from e
            elif e.code == 400:
                # Bad request (HTTP level)
                raise InvalidRequest(e.reason, e.code) from e
            else:
                raise
        except urllib.error.URLError as e:
            # Handle URL library errors
            raise RequestError(e.reason) from e

        # Log the request
        logger.debug("{0[method]} {0[url]} {1}".format(response[1], response[0]["Status"]))

        # Check for general errors
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

    def auth(self, username, password):
        # Check that we don't have a blank username/password
        if not isinstance(username, str) or username == "":
            raise ValueError("Username cannot be blank")
        if not isinstance(password, str) or password == "":
            raise ValueError("Password cannot be blank")

        # Get the request together
        endpoint = endpoints.user_accessgrant.format(username)
        data = {"Password": password}

        response = self.request(endpoint, endpoints.Methods.POST, data=data, check_request=False)

        if response["Status"] == 200:
            return response["Result"]
        elif response["Status"] == 401 or response["Status"] == 404 or response["Status"] == 400:
            # No such user/Bad password/Blank password
            raise AuthenticationFailure(response["Message"], response["Status"])
        else:
            return False

    def deauth(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        # Get the request together
        endpoint = endpoints.user_accessgrant.format(guid)
        data = {"AccessGrant": grant}

        response = self.request(endpoint, endpoints.Methods.PUT, auth=grant, data=data)

        if response["Status"] == 200:
            return True
        else:
            return False

    def user_account(self, grant, identifier):
        # Check that we don't have a blank identifier
        if not isinstance(identifier, str) or identifier == "":
            raise ValueError("Identifier cannot be blank")

        endpoint = endpoints.user.format(identifier)

        try:
            response = self.request(endpoint, endpoints.Methods.GET, auth=grant)
        except NotAuthorized as ex:
            if not ex.expired:
                raise WrongOwner(ex.message, ex.code)
            else:
                raise

        return response["Result"]

    def user_publicdata(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.user_publicdata_single.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def user_guid(self, callsign):
        # Check that we don't have a blank callsign
        if not isinstance(callsign, str) or callsign == "":
            raise ValueError("Callsign cannot be blank")

        endpoint = endpoints.uniquevalues_callsign.format(callsign)
        response = self.request(endpoint, endpoints.Methods.GET)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]["UserGuid"]

    def user_server(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.server_user.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def user_stats_batch(self, grant, guids):
        # Batch request
        if len(guids) == 0:
            raise ValueError("List of user GUIDs cannot be empty")

        endpoint = endpoints.user_stat_batch.format()
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant, batch=guids)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def user_stats_single(self, grant, guid):
        # Single request
        if guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.user_stat_single.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def server_list(self, grant):
        endpoint = endpoints.server.format()
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        return response["Result"]

    def server_single(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("Server GUID cannot be blank")

        endpoint = endpoints.server_single.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]

    def matchmaking_advertisement(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("Advertisement GUID cannot be blank")

        endpoint = endpoints.advertisement_single.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        if response["Status"] == 404:
            return None
        else:
            # Fix a bug in the API where a newline is appended to the server ip
            if response["Result"]["AssignedServerIp"] is not None:
                response["Result"]["AssignedServerIp"] = response["Result"]["AssignedServerIp"].strip("\n")

            return response["Result"]

    def matchmaking_advertisement_post(self, grant, advertisement):
        endpoint = endpoints.advertisement.format()
        response = self.request(endpoint, endpoints.Methods.POST, auth=grant, data=advertisement)

        if response["Status"] == 403:
            raise WrongOwner(response["Message"], response["Status"])

        return response["Result"]

    def matchmaking_advertisement_delete(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("Advertisement GUID cannot be blank")

        endpoint = endpoints.advertisement_single.format(guid)
        response = self.request(endpoint, endpoints.Methods.DELETE, auth=grant)

        if response["Status"] == 403:
            raise WrongOwner(response["Message"], response["Status"])
        if response["Status"] == 404:
            return None
        elif response["Status"] == 200:
            return True
        else:
            return False

    def generate_advertisement_matchmaking(self, gameversion, region, owner, users, gametype=None, party=None):
        # Check the parameters given
        if not isinstance(gameversion, str) or gameversion == "":
            raise ValueError("Game Version cannot be blank")
        if not isinstance(region, str) or region == "":
            raise ValueError("Region cannot be blank")
        if not isinstance(owner, str) or owner == "":
            raise ValueError("Owner cannot be blank")
        if len(users) == 0:
            raise ValueError("Users list cannot be empty")

        advertisement = {
            "GameVersion": gameversion,
            "OwnerGuid": owner,
            "Region": region,
            "Users": users
        }

        if gametype is not None:
            if not isinstance(gametype, str) or gametype == "":
                raise ValueError("Game Type cannot be blank")
            advertisement["GameType"] = gametype

        if party is not None:
            if not isinstance(party, str) or party == "":
                raise ValueError("Party GUID cannot be blank")
            advertisement["PartyGuid"] = party

        return advertisement

    def generate_advertisement_server(self, gameversion, region, server, owner, users, party=None):
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

        return advertisement

    def presence_access(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.presence_access.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        return response["Result"]

    def presence_domain(self, grant, guid):
        # Check that we don't have a blank guid
        if not isinstance(guid, str) or guid == "":
            raise ValueError("User GUID cannot be blank")

        endpoint = endpoints.presence_domain.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        return response["Result"]

    def game_items(self, grant):
        endpoint = endpoints.item.format()
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        return response["Result"]

    def game_items_single(self, grant, guid):
        if not isinstance(guid, str) or guid == "":
            raise ValueError("Item GUID cannot be blank")

        endpoint = endpoints.item_single.format(guid)
        response = self.request(endpoint, endpoints.Methods.GET, auth=grant)

        if response["Status"] == 404:
            return None
        else:
            return response["Result"]
