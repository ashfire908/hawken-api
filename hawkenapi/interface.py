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
from hawkenapi.endpoints import Methods
from hawkenapi.exceptions import AuthenticationFailure, NotAuthorized, InternalServerError, \
    ServiceUnavailable, WrongUser, InvalidRequest, InvalidBatch, InvalidResponse, auth_exception, \
    RequestError, NotAllowed, InsufficientFunds, InvalidStatTransfer
from hawkenapi.util import verify_guid

__all__ = ["Interface", "auth", "deauth", "achievement_list", "achievement_batch", "achievement_reward_list",
           "achievement_reward_single", "achievement_reward_batch", "achievement_user_list", "achievement_user_batch",
           "achievement_user_unlock", "antiaddiction", "clan_list", "clan_single", "clan_users", "currency_hawken",
           "currency_meteor", "events_url", "game_items", "game_items_single", "game_items_batch", "game_offers_list",
           "game_offers_single", "game_offers_batch", "game_offers_redeem", "game_offers_rent",
           "generate_advertisement_matchmaking", "generate_advertisement_server", "matchmaking_advertisement",
           "matchmaking_advertisement_create", "matchmaking_advertisement_delete", "presence_access", "presence_domain",
           "server_list", "server_single", "stat_overflow_list", "stat_overflow_single", "stat_overflow_transfer_from",
           "stat_overflow_transfer_to", "status_game", "status_services", "user_transaction", "uniquevalues_list",
           "user_account", "user_clan", "user_eula_read", "user_game_settings", "user_game_settings_create",
           "user_game_settings_update", "user_game_settings_delete", "user_guid", "user_items", "user_items_batch",
           "user_items_broker", "user_items_stats", "user_items_stats_single", "user_meteor_settings",
           "user_publicdata_single", "user_server", "user_stats_single", "user_stats_batch", "version", "voice_access",
           "voice_info", "voice_lookup", "voice_user", "voice_channel"]

# Setup logging
logger = logging.getLogger(__name__)


# Interface
class Interface:
    def __init__(self, host=None, stack=None, scheme="http"):
        # Set the host and scheme
        if host:
            # Use given host
            self.host = host
        elif stack:
            # Set host by 'stack'
            self.host = "{0}.hawken.meteor-ent.com".format(stack)
        else:
            # Use default host
            self.host = "services.live.hawken.meteor-ent.com"

        self.scheme = scheme

    def _build_endpoint(self, endpoint, *args, **kwargs):
        return "{0}://{1}/{2}".format(self.scheme, self.host, endpoint.format(*args, **kwargs))

    def _build_request(self, url, method, auth, data, batch):
        # Encode data
        if data:
            body = json.dumps(data).encode()
        else:
            body = None

        # Create the request
        request = urllib.request.Request(url, data=body, method=method)

        # Add the headers
        if auth:
            request.add_header("Authorization", "Basic %s" % auth)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if batch:
            request.add_header("X-Meteor-Batch", ",".join(batch))

        return request

    def _perform_request(self, request):
        # Add global headers
        request.add_header("User-Agent", "HawkenApi/{0}".format(hawkenapi.__version__))
        request.add_header("Accept-Encoding", "gzip")

        try:
            # Open the connection
            connection = urllib.request.urlopen(request)
            try:
                # Load the data
                response = connection.read()

                # Grab the info we need
                charset = connection.info().get_content_charset("utf-8")  # Fallback: UTF-8
                content_encoding = connection.getheader("Content-Encoding")
            except:
                logger.error("Exception at response - {0} {1}".format(request.method, connection.url))
                raise
            finally:
                # Close the connection
                connection.close()
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

        return json.loads(response.decode(charset)), {"url": connection.url, "method": request.method}

    def _request(self, method, endpoint, *args, check=True, auth=None, data=None, batch=None, **kwargs):
        # Verify endpoint support
        if method not in endpoint.methods:
            raise ValueError("Endpoint does not support {0} method".format(method))
        if data and method == Methods.GET:
            raise ValueError("The {0} method does not take a request body".format(method))
        if not auth and endpoint.flags.authrequired:
            raise ValueError("Endpoint requires an access grant")
        if batch and not endpoint.flags.batchheader:
            raise ValueError("Endpoint does not support batched requests")

        try:
            # Create the API request
            request = self._build_request(self._build_endpoint(endpoint, *args, **kwargs), method, auth, data, batch)

            # Perform the request
            response = self._perform_request(request)
        except http.client.BadStatusLine as e:
            # Handle bad status error (network error)
            raise RequestError("HTTP Bad Status") from e
        except urllib.error.HTTPError as e:
            # Handle HTTP errors
            if e.code == 503:
                # Service unavailable (usually backend at capacity)
                raise ServiceUnavailable(e.reason, e.code) from e
            if e.code == 500:
                # Internal server error (HTTP level)
                raise InternalServerError(e.reason, e.code) from e
            if e.code == 400:
                # Bad request (HTTP level)
                raise InvalidRequest(e.reason, e.code) from e

            raise
        except urllib.error.URLError as e:
            # Handle URL library errors
            raise RequestError(e.reason) from e

        # Log the request
        logger.debug("{0[method]} {0[url]} {1}".format(response[1], response[0]["Status"]))

        # Check for server errors
        if response[0]["Status"] == 500:
            raise InternalServerError(response[0]["Message"], response[0]["Status"])
        if check:
            # Check for auth errors
            if response[0]["Status"] == 401:
                auth_exception(response[0])
            # Check for batch header errors
            if response[0]["Status"] == 400 and endpoint.flags.batchheader and (
               response[0]["Message"] == "Batch request must contain valid guids in 'x-meteor-batch'." or
               response[0]["Message"] == "Invalid users ID"):
                raise InvalidBatch(response[0]["Message"], response[0]["Status"], response[0].get("Result", None))
            # Check for invalid request errors
            if response[0]["Status"] == 400:
                raise InvalidRequest(response[0]["Message"], response[0]["Status"])

        # Return the response data
        return response[0]

    def get(self, endpoint, *args, **kwargs):
        return self._request(Methods.GET, endpoint, *args, **kwargs)

    def post(self, endpoint, *args, **kwargs):
        return self._request(Methods.POST, endpoint, *args, **kwargs)

    def put(self, endpoint, *args, **kwargs):
        return self._request(Methods.PUT, endpoint, *args, **kwargs)

    def delete(self, endpoint, *args, **kwargs):
        return self._request(Methods.DELETE, endpoint, *args, **kwargs)


def auth(interface, username, password):
    # Validate the username and password
    if not isinstance(username, str) or username == "":
        raise ValueError("Username cannot be blank")
    if not isinstance(password, str) or password == "":
        raise ValueError("Password cannot be blank")

    data = {"Password": password}

    response = interface.post(endpoints.user_accessgrant, username, data=data, check=False)

    if response["Status"] == 200:
        # Return response
        return response["Result"]

    if response["Status"] == 401 or response["Status"] == 404 or response["Status"] == 400:
        # Rejected authentication (No such user/Blank password/Incorrect password)
        raise AuthenticationFailure(response["Message"], response["Status"])

    # Catch all failure
    return False


def deauth(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    data = {"AccessGrant": grant}

    response = interface.put(endpoints.user_accessgrant, guid, auth=grant, data=data, check=False)

    if response["Status"] == 200:
        # Success
        return True

    if response["Status"] == 401:
        if NotAuthorized.is_revoked(response["Message"]):
            # Already revoked
            return True

        # Auth failure
        auth_exception(response)

    # Catch all failure
    return False


def achievement_list(interface, grant, countrycode=None):
    response = interface.get(endpoints.achievement, auth=grant, countrycode=countrycode)

    # Return the achievement list
    return response["Result"]


def achievement_batch(interface, grant, guids, countrycode=None):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of achievement GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement GUID given")

    response = interface.get(endpoints.achievement_batch, auth=grant, batch=guids, countrycode=countrycode)

    # Return response
    return response["Result"]


def achievement_reward_list(interface, grant, countrycode=None):
    response = interface.get(endpoints.achievement_reward, auth=grant, countrycode=countrycode)

    # Return response
    return response["Result"]


def achievement_reward_single(interface, grant, guid, countrycode=None):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid achievement reward GUID given")

    response = interface.get(endpoints.achievement_reward_single, guid, auth=grant, countrycode=countrycode)

    if response["Status"] == 404:
        # No such reward
        return None

    # Return response
    return response["Result"]


def achievement_reward_batch(interface, grant, guids, countrycode=None):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of achievement reward GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement reward GUID given")

    response = interface.get(endpoints.achievement_reward_batch, auth=grant, batch=guids, countrycode=countrycode)

    # Return response
    return response["Result"]


def achievement_user_list(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.achievement_user, guid, auth=grant)

    if response["Status"] == 404:
        if response["Message"] == "User not found":
            # No such user
            return None

        # No achievements for the user
        return []

    # Return response
    return response["Result"]


def achievement_user_batch(interface, grant, user, achievements):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if len(achievements) == 0:
        raise ValueError("List of achievement GUIDs cannot be empty")
    for guid in achievements:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement GUID given")

    response = interface.get(endpoints.achievement_user, user, auth=grant, batch=achievements)

    if response["Status"] == 404:
        if response["Message"] == "Error retrieving batch items.":
            # No such achievement
            raise InvalidBatch(response["Message"], response["Status"], None)

        # No such user
        return None

    # Return response
    return response["Result"]


def achievement_user_unlock(interface, grant, user, achievement):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(user):
        raise ValueError("Invalid achievement GUID given")

    response = interface.post(endpoints.achievement_user_client, user, achievement, auth=grant)

    if response["Status"] == 403:
        if response["Message"] == "Requesting access grant's user GUID must match user GUID parameter":
            # User does not match access grant user
            raise WrongUser(response["Message"], response["Status"])

        if response["Message"] == "Achievement is already redeemed":
            # Achievement already unlocked
            return False

        # Can't be unlocked from client
        raise InvalidRequest(response["Message"], response["Status"])

    if response["Status"] == 404:
        # No such achievement
        return None

    # Success
    return True


def antiaddiction(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.antiaddiction, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def clan_list(interface, grant, tag=None, name=None):
    response = interface.get(endpoints.clan, auth=grant, clantag=tag, clanname=name)

    # Return response
    return response["Result"]


def clan_single(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid clan GUID given")

    response = interface.get(endpoints.clan_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such clan
        return None

    # Return response
    return response["Result"]


def clan_users(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid clan GUID given")

    response = interface.get(endpoints.clan_users, guid, auth=grant)

    if response["Status"] == 404:
        # No such clan
        return None

    # Return response
    return response["Result"]


def currency_hawken(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.currency_game, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def currency_meteor(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.currency_meteor, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def events_url(interface):
    response = interface.get(endpoints.eventsurl)

    # Return response
    return response["Result"]


def game_items(interface, grant):
    response = interface.get(endpoints.item, auth=grant)

    # Return response
    return response["Result"]


def game_items_single(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid item GUID given")

    response = interface.get(endpoints.item_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such item
        return None

    # Return response
    return response["Result"]


def game_items_batch(interface, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of item GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid item GUID given")

    response = interface.post(endpoints.item_batch, auth=grant, data=guids)

    if response["Status"] == 404:
        # No such item
        raise InvalidBatch(response["Message"], response["Status"], None)

    # Return response
    return response["Result"]


def game_offers_list(interface, grant):
    response = interface.get(endpoints.offer, auth=grant)

    # Return response
    return response["Result"]


def game_offers_single(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid offer GUID given")

    response = interface.get(endpoints.offer, auth=grant)

    if response["Status"] == 404:
        # No such offer
        return None

    # Return response
    return response["Result"]


def game_offers_batch(interface, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of offer GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid offer GUID given")

    response = interface.post(endpoints.offer_batch, auth=grant, data=guids)

    if response["Status"] == 404:
        # No such offer
        raise InvalidBatch(response["Message"], response["Status"], None)

    # Return response
    return response["Result"]


def game_offers_redeem(interface, grant, user, offer, currency, transaction, parent=None):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(offer):
        raise ValueError("Invalid offer GUID given")
    if not currency in ("HP", "MP"):
        raise ValueError("Invalid currency given")
    if not verify_guid(transaction):
        raise ValueError("Invalid transaction GUID given")

    data = {"Currency": currency,
            "TransactionId": transaction}

    if parent is not None:
        if not verify_guid(parent):
            raise ValueError("Invalid parent item GUID given")
        data["ExistingParentInstanceGuid"] = parent

    try:
        response = interface.post(endpoints.offer_redeemer, user, offer, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 404:
        if response["Message"] == "No valid transaction for user {0} with id {1}".format(user, transaction):
            # Invalid transaction
            raise InvalidRequest(response["Message"], response["Status"])

        if response["Message"] == "No items found":
            # No such parent item
            raise InvalidRequest(response["Message"], response["Status"])

        # No such offer
        return None

    if response["Status"] == 412:
        # Not enough currency
        raise InsufficientFunds(response["Message"], response["Status"])

    # Return response
    return response["Result"]


def game_offers_rent(interface, grant, user, offer, currency, transaction, parent=None):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(offer):
        raise ValueError("Invalid offer GUID given")
    if not currency in ("HP", "MP"):
        raise ValueError("Invalid currency given")
    if not verify_guid(transaction):
        raise ValueError("Invalid transaction GUID given")

    data = {"Currency": currency,
            "TransactionId": transaction}

    if parent is not None:
        if not verify_guid(parent):
            raise ValueError("Invalid parent item GUID given")
        data["ExistingParentInstanceGuid"] = parent

    try:
        response = interface.post(endpoints.offer_renter, user, offer, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 404:
        if response["Message"] == "No valid transaction for user {0} with id {1}".format(user, transaction):
            # Invalid transaction
            raise InvalidRequest(response["Message"], response["Status"])

        if response["Message"] == "No items found":
            # No such parent item
            raise InvalidRequest(response["Message"], response["Status"])

        # No such offer
        return None

    if response["Status"] == 412:
        # Not enough currency
        raise InsufficientFunds(response["Message"], response["Status"])

    # Return response
    return response["Result"]


def generate_advertisement_matchmaking(gameversion, region, owner, users, gametype=None, party=None):
    # Check the parameters given
    if not isinstance(gameversion, str) or gameversion == "":
        raise ValueError("Game Version cannot be blank")
    if not isinstance(region, str) or region == "":
        raise ValueError("Region cannot be blank")
    if not verify_guid(owner):
        raise ValueError("Invalid owner GUID given")
    if len(users) == 0:
        raise ValueError("List of user GUIDs cannot be empty")
    for guid in users:
        if not verify_guid(guid):
            raise ValueError("Invalid user GUID given")

    # Build base advertisement
    advertisement = {
        "GameVersion": gameversion,
        "OwnerGuid": owner,
        "Region": region,
        "Users": users
    }

    if gametype is not None:
        # Check and add gametype
        if not isinstance(gametype, str) or gametype == "":
            raise ValueError("Game Type cannot be blank")
        advertisement["GameType"] = gametype

    if party is not None:
        # Check and add party
        if not verify_guid(party):
            raise ValueError("Invalid party GUID given")
        advertisement["PartyGuid"] = party

    # Return advertisement
    return advertisement


def generate_advertisement_server(gameversion, region, server, owner, users, party=None):
    # Check the parameters given
    if not isinstance(gameversion, str) or gameversion == "":
        raise ValueError("Game Version cannot be blank")
    if not isinstance(region, str) or region == "":
        raise ValueError("Region cannot be blank")
    if not verify_guid(server):
        raise ValueError("Invalid server GUID given")
    if not verify_guid(owner):
        raise ValueError("Invalid owner GUID given")
    if len(users) == 0:
        raise ValueError("List of user GUIDs cannot be empty")
    for guid in users:
        if not verify_guid(guid):
            raise ValueError("Invalid user GUID given")

    # Build base advertisement
    advertisement = {
        "GameVersion": gameversion,
        "OwnerGuid": owner,
        "Region": region,
        "RequestedServerGuid": server,
        "Users": users
    }

    if party is not None:
        # Check and add party
        if not verify_guid(party):
            raise ValueError("Invalid party GUID given")
        advertisement["PartyGuid"] = party

    # Return advertisement
    return advertisement


def matchmaking_advertisement(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid advertisement GUID given")

    response = interface.get(endpoints.advertisement_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such advertisement
        return None

    # Fix incomplete request marked as ready
    if response["Result"]["ReadyToDeliver"] and \
       (response["Result"]["AssignedServerIp"] in (None, "") or response["Result"]["AssignedServerPort"] == 0):
        response["Result"]["ReadyToDeliver"] = False
        logger.debug("Unmarked ready to deliver on incomplete reservation.")

    # Fix newline appended to the server IP
    if response["Result"]["AssignedServerIp"] is not None:
        response["Result"]["AssignedServerIp"] = response["Result"]["AssignedServerIp"].strip("\n")

    # Check for requested/assigned server mismatch
    if response["Result"]["ReadyToDeliver"] and \
       response["Result"]["RequestedServerGuid"] != "00000000-0000-0000-0000-000000000000" and \
       response["Result"]["AssignedServerGuid"] != response["Result"]["RequestedServerGuid"]:
        logger.error("Requested server GUID does not matched assigned server GUID.")
        raise InvalidResponse("Requested server GUID does not matched assigned server GUID", response["Status"], response["Result"])

    # Return response
    return response["Result"]


def matchmaking_advertisement_create(interface, grant, advertisement):
    response = interface.post(endpoints.advertisement, auth=grant, data=advertisement)

    if response["Status"] == 403:
        # Owner does not match access grant user
        raise WrongUser(response["Message"], response["Status"])

    # Return result
    return response["Result"]


def matchmaking_advertisement_delete(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid advertisement GUID given")

    response = interface.delete(endpoints.advertisement_single, guid, auth=grant)

    if response["Status"] == 403:
        # Owner does not match access grant user
        raise WrongUser(response["Message"], response["Status"])

    if response["Status"] == 404:
        # No such advertisement
        return None

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def presence_access(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.get(endpoints.presence_access, guid, auth=grant)
    except NotAuthorized as e:
        if e.message == "Access grant with matching user GUID required":
            # User does not match access grant user
            raise WrongUser(e.message, e.code)

        raise

    # Return response
    return response["Result"]


def presence_domain(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.get(endpoints.presence_domain, guid, auth=grant)
    except NotAuthorized as e:
        if e.message == "Access grant with matching user GUID required":
            # User does not match access grant user
            raise WrongUser(e.message, e.code)

        raise

    # Return response
    return response["Result"]


def server_list(interface, grant):
    response = interface.get(endpoints.server, auth=grant)

    # Return response
    return response["Result"]


def server_single(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid server GUID given")

    response = interface.get(endpoints.server_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such server
        return None

    # Return response
    return response["Result"]


def stat_overflow_list(interface, grant):
    response = interface.get(endpoints.statoverflow, auth=grant)

    # Return response
    return response["Result"]


def stat_overflow_single(interface, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid overflow GUID given")

    response = interface.get(endpoints.statoverflow_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such overflow
        return None

    # Return response
    return response["Result"]


def stat_overflow_transfer_from(interface, grant, user, instance, overflow, amount):
    # Verify guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid mech instance GUID given")
    if not verify_guid(overflow):
        raise ValueError("Invalid overflow GUID given")
    if amount < 1:
        raise ValueError("Must transfer at least 1 point")

    data = {"Amount": amount, "OverflowId": overflow}

    try:
        response = interface.put(endpoints.statoverflow_transfer, user, instance, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)
    except InvalidRequest as e:
        new_e = InvalidStatTransfer(e.message, e.code)
        if new_e.is_match:
            # Invalid stat transfer operation
            raise new_e

        raise

    if response["Status"] == 404:
        if response["Message"] == "{0} not found".format(overflow):
            # No such overflow
            raise InvalidRequest(response["Message"], response["Status"])

        # No such item
        return None

    if response["Status"] == 412:
        # Not enough currency
        raise InsufficientFunds(response["Message"], response["Status"])

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def stat_overflow_transfer_to(interface, grant, user, instance, overflow, amount):
    # Verify guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid mech instance GUID given")
    if not verify_guid(overflow):
        raise ValueError("Invalid overflow GUID given")
    if amount < 1:
        raise ValueError("Must transfer at least 1 point")

    data = {"Amount": amount, "OverflowId": overflow}

    try:
        response = interface.put(endpoints.statoverflow_transfer, user, instance, auth=grant, data=data)
        # FIXME: Total universal XP not validated before transaction
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)
    except InvalidRequest as e:
        new_e = InvalidStatTransfer(e.message, e.code)
        if new_e.is_match:
            # Invalid stat transfer operation
            raise new_e

        raise

    if response["Status"] == 404:
        if response["Message"] == "{0} not found".format(overflow):
            # No such overflow
            raise InvalidRequest(response["Message"], response["Status"])

        # No such item
        return None

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def status_game(interface):
    response = interface.get(endpoints.status_gameclient)

    # Return response
    return response


def status_services(interface):
    response = interface.get(endpoints.status_services)

    # Return response
    return response


def uniquevalues_list(interface):
    response = interface.get(endpoints.uniquevalues)

    # Return response
    return response["Result"]


def user_account(interface, grant, identifier):
    # Check that we don't have a blank identifier
    if not isinstance(identifier, str) or identifier == "":
        raise ValueError("Identifier cannot be blank")

    try:
        response = interface.get(endpoints.user, identifier, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    # Return response
    return response["Result"]


def user_clan(interface, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_clan, guid, auth=grant)

    if response["Status"] == 404:
        # No such user/User is not in a clan
        return None

    # Return response
    return response["Result"]


def user_eula_read(interface, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.get(endpoints.user_eula, guid, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    # Return response
    return response["Result"]


def user_game_settings(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_settings_single, guid, auth=grant)

    if response["Status"] == 404:
        # No game settings found
        return None

    # Return response
    return response["Result"]


def user_game_settings_create(interface, grant, guid, data):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.post(endpoints.user_settings_single, guid, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 201:
        # Success
        return True

    # Catch all failure
    return False


def user_game_settings_update(interface, grant, guid, data):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.put(endpoints.user_settings_single, guid, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 404:
        # No game settings exists
        return None

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def user_game_settings_delete(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.delete(endpoints.user_settings_single, guid, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 404:
        # No game settings exists
        return None

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def user_guid(interface, callsign):
    # Check that we don't have a blank callsign
    if not isinstance(callsign, str) or callsign == "":
        raise ValueError("Callsign cannot be blank")

    response = interface.get(endpoints.uniquevalues_callsign, callsign)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]["UserGuid"]


def user_items(interface, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_item, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_items_batch(interface, grant, user, items):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if len(items) == 0:
        raise ValueError("List of item instance GUIDs cannot be empty")
    for guid in items:
        if not verify_guid(guid):
            raise ValueError("Invalid item instance GUID given")

    response = interface.post(endpoints.user_item_batch, user, auth=grant, data=items)

    if response["Status"] == 404:
        if response["Message"] == "Error retrieving batch user game items. If any item doesn't exist the batch will fail.":
            # No such achievement
            raise InvalidBatch(response["Message"], response["Status"], None)

        # No such user
        return None

    # Return response
    return response["Result"]


def user_items_broker(interface, grant, user, instance, data):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid item instance GUID given")

    try:
        response = interface.put(endpoints.user_item_broker, user, instance, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 403:
        # Action not allowed
        raise NotAllowed(response["Message"], response["Status"])

    if response["Status"] == 404:
        # No such item
        return None

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def user_items_stats(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_item_stat, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_items_stats_single(interface, grant, user, instance):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid item instance GUID given")

    response = interface.get(endpoints.user_item_stat_single, user, instance, auth=grant)

    if response["Status"] == 404:
        if response["Message"] == "No items found":
            # No such item
            return None

        # No such user
        return False

    # Return response
    return response["Result"]


def user_meteor_settings(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = interface.get(endpoints.user_meteor_single, guid, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    # Return response
    return response["Result"]


def user_publicdata_single(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_publicdata_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_server(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.server_user, guid, auth=grant)

    if response["Status"] == 404:
        # No such user/user is not on a server
        return None

    # Return response
    return response["Result"]


def user_stats_single(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_stat_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_stats_batch(interface, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of user GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.user_stat_batch, auth=grant, batch=guids)

    # Return response
    return response["Result"]


def user_transaction(interface, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.post(endpoints.transaction, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    if response["Status"] == 201:
        # Return response
        return response["Result"]

    # Catch all failure
    return False


def version(interface):
    response = interface.get(endpoints.version)

    # Return response
    return response["Result"]


def voice_access(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.voice_access, guid, auth=grant)

    # Return response
    return response["Result"]


def voice_info(interface, grant):
    response = interface.get(endpoints.voice_info, auth=grant)

    # Return response
    return response["Result"]


def voice_lookup(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid vivox user GUID given")

    response = interface.get(endpoints.voice_lookup, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def voice_user(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = interface.get(endpoints.voice_user, guid, auth=grant)

    # Return response
    return response["Result"]


def voice_channel(interface, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid channel GUID given")

    response = interface.get(endpoints.voice_channel, guid, auth=grant)

    # Return response
    return response["Result"]
