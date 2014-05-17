# -*- coding: utf-8 -*-
# Low-level API interface
# Copyright (c) 2013-2014 Andrew Hampe

import requests
from requests.auth import AuthBase
from requests.adapters import HTTPAdapter, DEFAULT_POOLSIZE, DEFAULT_RETRIES
import json
import hawkenapi
from hawkenapi import endpoints
from hawkenapi.endpoints import Methods
from hawkenapi.exceptions import AuthenticationFailure, NotAuthorized, InternalServerError, \
    ServiceUnavailable, WrongUser, InvalidRequest, InvalidBatch, InvalidResponse, NotAuthenticated, \
    NotAllowed, InsufficientFunds, InvalidStatTransfer, AccountBanned, AccountDeactivated
from hawkenapi.util import verify_guid, chunks

__all__ = ["Session", "auth", "deauth", "achievement_list", "achievement_batch", "achievement_reward_list",
           "achievement_reward_single", "achievement_reward_batch", "achievement_user_list", "achievement_user_batch",
           "achievement_user_unlock", "antiaddiction", "clan_list", "clan_single", "clan_users", "currency_hawken",
           "currency_meteor", "events_url", "game_items", "game_items_single", "game_items_batch", "game_offers_list",
           "game_offers_single", "game_offers_batch", "game_offers_redeem", "game_offers_rent",
           "generate_advertisement_matchmaking", "generate_advertisement_server", "matchmaking_advertisement",
           "matchmaking_advertisement_create", "matchmaking_advertisement_delete", "presence_access", "presence_domain",
           "server_list", "server_single", "stat_overflow_list", "stat_overflow_single", "stat_overflow_transfer_from",
           "stat_overflow_transfer_to", "status_game_client", "status_game_servers", "status_services",
           "user_transaction", "uniquevalues_list", "user_account", "user_clan", "user_eula_read", "user_game_settings",
           "user_game_settings_create", "user_game_settings_update", "user_game_settings_delete", "user_guid",
           "user_items", "user_items_batch", "user_items_broker", "user_items_stats", "user_items_stats_single",
           "user_meteor_settings", "user_publicdata_single", "user_server", "user_stats_single", "user_stats_batch",
           "version", "voice_access", "voice_info", "voice_lookup", "voice_user", "voice_channel", "bundle_list",
           "bundle_single", "bundle_batch"]

batch_limit = 200


# Auth handler
class MeteorAuth(AuthBase):
    def __init__(self, grant):
        self.grant = str(grant)

    def __call__(self, r):
        r.headers["Authorization"] = "Basic {0}".format(self.grant)
        return r


# Session
class Session(requests.Session):
    def __init__(self, host=None, stack=None, scheme=None, timeout=None, pool_connections=DEFAULT_POOLSIZE, pool_maxsize=DEFAULT_POOLSIZE, max_retries=DEFAULT_RETRIES):
        super(Session, self).__init__()

        # Set the user agent
        self.headers["User-Agent"] = "HawkenApi/{0}".format(hawkenapi.__version__)

        # Set the host
        if host:
            self.host = host
        elif stack:
            self.stack = stack
        else:
            self.host = "services.live.hawken.meteor-ent.com"

        # Set the scheme
        if scheme:
            self.scheme = scheme
        else:
            self.scheme = "http"

        # Set the timeout
        self.timeout = timeout

        # Set up the adapter
        adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize, max_retries=max_retries)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value
        self._stack = None

    @property
    def stack(self):
        return self._stack

    @stack.setter
    def stack(self, value):
        self._host = "{0}.hawken.meteor-ent.com".format(value)
        self._stack = value

    @property
    def scheme(self):
        return self._scheme

    @scheme.setter
    def scheme(self, value):
        if value not in ("http", "https"):
            raise ValueError("Invalid scheme - must be either 'http' or 'https'")

        self._scheme = value

    def format_endpoint(self, endpoint, *args):
        return "{0}://{1}/{2}".format(self.scheme, self.host, endpoint.format_url(*args))

    def build_request(self, method, endpoint, *args, auth=None, data=None, batch=None, **fields):
        headers = {}

        # Verify endpoint support
        if method not in endpoint.methods:
            raise ValueError("Endpoint does not support {0} method".format(method))
        if data and method == Methods.get:
            raise ValueError("The {0} method does not take a request body".format(method))
        if not auth and endpoint.flags.authrequired:
            raise ValueError("Endpoint requires an access grant")

        # Get the url
        url = self.format_endpoint(endpoint, *args)

        # Handle auth
        if auth:
            auth = MeteorAuth(auth)

        # Handle batch
        if batch:
            if endpoint.flags.batchheader:
                # Batch header
                headers["X-Meteor-Batch"] = ",".join(batch)
            elif endpoint.flags.batchpost:
                if data:
                    raise ValueError("Endpoint cannot take data in a batched request")

                # Batch body
                data = batch
            else:
                raise ValueError("Endpoint does not support batched requests")

        # Handle data
        if data:
            data = json.dumps(data)
            headers["Content-Type"] = "application/json"

        # Prepare the request
        request = self.prepare_request(requests.Request(method, url, headers=headers, data=data, params=endpoint.format_fields(**fields), auth=auth))

        return request

    def perform_request(self, request, check=True):
        response = self.send(request, timeout=self.timeout)

        # Check for HTTP errors
        if response.status_code != requests.codes.ok:
            if response.status_code == requests.codes.service_unavailable:
                raise ServiceUnavailable(response.reason, response.status_code)
            if response.status_code == requests.codes.internal_server_error:
                raise InternalServerError(response.reason, response.status_code)
            if response.status_code == requests.codes.bad_request:
                raise InvalidRequest(response.reason, response.status_code)

            response.raise_for_status()

        reply = response.json()

        # Check for server errors
        if reply["Status"] == 500:
            raise InternalServerError(reply["Message"], reply["Status"])

        if check:
            # Check for authentication errors
            if reply["Status"] == 401:
                if NotAuthenticated.is_missing(reply["Message"]):
                    # Missing authentication
                    raise NotAuthenticated(reply["Message"], reply["Status"])
                if NotAllowed.is_denied(reply["Message"]):
                    # Denied access
                    raise NotAllowed(reply["Message"], reply["Status"])
                if AuthenticationFailure.is_badpass(reply["Message"]):
                    # Bad password
                    raise AuthenticationFailure(reply["Message"], reply["Status"])

                # General authentication error
                raise NotAuthorized(reply["Message"], reply["Status"])

            # Check for invalid request errors
            if reply["Status"] == requests.codes.bad_request:
                # Check for batch header errors
                if "X-Meteor-Batch" in response.request.headers and (
                   reply["Message"] == "Batch request must contain valid guids in 'x-meteor-batch'." or
                   reply["Message"] == "Invalid users ID"):
                    raise InvalidBatch(reply["Message"], reply["Status"], reply.get("Result", None))

                raise InvalidRequest(reply["Message"], reply["Status"])

        # Return JSON reply
        return reply

    def api_call(self, method, endpoint, *args, auth=None, data=None, batch=None, check=True, **fields):
        request = self.build_request(method, endpoint, *args, auth=auth, data=data, batch=batch, **fields)
        return self.perform_request(request, check=check)

    def api_get(self, endpoint, *args, **kwargs):
        return self.api_call(Methods.get, endpoint, *args, **kwargs)

    def api_post(self, endpoint, *args, **kwargs):
        return self.api_call(Methods.post, endpoint, *args, **kwargs)

    def api_put(self, endpoint, *args, **kwargs):
        return self.api_call(Methods.put, endpoint, *args, **kwargs)

    def api_delete(self, endpoint, *args, **kwargs):
        return self.api_call(Methods.delete, endpoint, *args, **kwargs)


def auth(session, username, password):
    # Validate the username and password
    if not isinstance(username, str) or username == "":
        raise ValueError("Username cannot be blank")
    if not isinstance(password, str) or password == "":
        raise ValueError("Password cannot be blank")

    data = {"Password": password}

    response = session.api_post(endpoints.user_accessgrant, username, data=data, check=False)

    if response["Status"] == 200:
        # Return response
        return response["Result"]

    if response["Status"] == 401 and response["Message"] == "User deactivated":
        # Account deactivated
        raise AccountDeactivated(response["Message"], response["Status"])

    if response["Status"] == 403:
        # Account banned
        raise AccountBanned(response["Message"], response["Status"], response["Result"])

    if response["Status"] == 401 or response["Status"] == 404 or response["Status"] == 400:
        # Rejected authentication (No such user/Blank password/Incorrect password)
        raise AuthenticationFailure(response["Message"], response["Status"])

    # Catch all failure
    return False


def deauth(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    data = {"AccessGrant": grant}

    try:
        response = session.api_put(endpoints.user_accessgrant, guid, auth=grant, data=data, check=False)
    except NotAuthorized as e:
        if e.revoked:
            # Already revoked
            return True

        raise

    if response["Status"] == 200:
        # Success
        return True

    # Catch all failure
    return False


def achievement_list(session, grant, countrycode=None):
    response = session.api_get(endpoints.achievement, auth=grant, countrycode=countrycode)

    # Return the achievement list
    return response["Result"]


def achievement_batch(session, grant, guids, countrycode=None):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of achievement GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, batch_limit):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.achievement_batch, auth=grant, batch=chunk, countrycode=countrycode)["Result"])

    # Return data set
    return data


def achievement_reward_list(session, grant, countrycode=None):
    response = session.api_get(endpoints.achievement_reward, auth=grant, countrycode=countrycode)

    # Return response
    return response["Result"]


def achievement_reward_single(session, grant, guid, countrycode=None):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid achievement reward GUID given")

    response = session.api_get(endpoints.achievement_reward_single, guid, auth=grant, countrycode=countrycode)

    if response["Status"] == 404:
        # No such reward
        return None

    # Return response
    return response["Result"]


def achievement_reward_batch(session, grant, guids, countrycode=None):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of achievement reward GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement reward GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, batch_limit):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.achievement_reward_batch, auth=grant, batch=chunk, countrycode=countrycode)["Result"])

    # Return data set
    return data


def achievement_user_list(session, grant, guid, countrycode=None):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.achievement_user, guid, auth=grant, countrycode=countrycode)

    if response["Status"] == 404:
        if response["Message"] == "User not found":
            # No such user
            return None

        # No achievements for the user
        return []

    # Return response
    return response["Result"]


def achievement_user_batch(session, grant, user, achievements, countrycode=None):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if len(achievements) == 0:
        raise ValueError("List of achievement GUIDs cannot be empty")
    for guid in achievements:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement GUID given")

    response = session.api_post(endpoints.achievement_user_query, user, auth=grant, batch=achievements, countrycode=countrycode)

    if response["Status"] == 404:
        if response["Message"] == "Error retrieving batch items.":
            # No such achievement
            raise InvalidBatch(response["Message"], response["Status"], None)

        # No such user
        return None

    # Return response
    return response["Result"]


def achievement_user_unlock(session, grant, user, achievement):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(user):
        raise ValueError("Invalid achievement GUID given")

    response = session.api_post(endpoints.achievement_user_client, user, achievement, auth=grant)

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


def antiaddiction(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.antiaddiction, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def bundle_list(session, grant):
    response = session.api_get(endpoints.bundle, auth=grant)

    # Return response
    return response["Result"]


def bundle_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid bundle GUID given")

    response = session.api_get(endpoints.bundle_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such bundle
        return None

    # Return response
    return response["Result"]


def bundle_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of bundle GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid bundle GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, batch_limit):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.bundle, auth=grant, batch=chunk)["Result"])

    # Return data set
    return data


def clan_list(session, grant, tag=None, name=None):
    response = session.api_get(endpoints.clan, auth=grant, clantag=tag, clanname=name)

    # Return response
    return response["Result"]


def clan_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid clan GUID given")

    response = session.api_get(endpoints.clan_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such clan
        return None

    # Return response
    return response["Result"]


def clan_users(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid clan GUID given")

    response = session.api_get(endpoints.clan_users, guid, auth=grant)

    if response["Status"] == 404:
        # No such clan
        return None

    # Return response
    return response["Result"]


def currency_hawken(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.currency_game, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def currency_meteor(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.currency_meteor, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def events_url(session):
    response = session.api_get(endpoints.eventsurl)

    # Return response
    return response["Result"]


def game_items(session, grant):
    response = session.api_get(endpoints.item, auth=grant)

    # Return response
    return response["Result"]


def game_items_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid item GUID given")

    response = session.api_get(endpoints.item_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such item
        return None

    # Return response
    return response["Result"]


def game_items_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of item GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid item GUID given")

    response = session.api_post(endpoints.item_batch, auth=grant, batch=guids)

    if response["Status"] == 404:
        # No such item
        raise InvalidBatch(response["Message"], response["Status"], None)

    # Return response
    return response["Result"]


def game_offers_list(session, grant):
    response = session.api_get(endpoints.offer, auth=grant)

    # Return response
    return response["Result"]


def game_offers_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid offer GUID given")

    response = session.api_get(endpoints.offer_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such offer
        return None

    # Return response
    return response["Result"]


def game_offers_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of offer GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid offer GUID given")

    response = session.api_post(endpoints.offer_batch, auth=grant, batch=guids)

    if response["Status"] == 404:
        # No such offer
        raise InvalidBatch(response["Message"], response["Status"], None)

    # Return response
    return response["Result"]


def game_offers_redeem(session, grant, user, offer, currency, transaction, parent=None):
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
        response = session.api_post(endpoints.offer_redeemer, user, offer, auth=grant, data=data)
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

    if response["Status"] == 403:
        # Offer is disabled
        raise InvalidRequest(response["Message"], response["Status"])

    if response["Status"] == 412:
        # Not enough currency
        raise InsufficientFunds(response["Message"], response["Status"])

    # Return response
    return response["Result"]


def game_offers_rent(session, grant, user, offer, currency, transaction, parent=None):
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
        response = session.api_post(endpoints.offer_renter, user, offer, auth=grant, data=data)
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


def matchmaking_advertisement(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid advertisement GUID given")

    response = session.api_get(endpoints.advertisement_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such advertisement
        return None

    # Fix incomplete request marked as ready
    if response["Result"]["ReadyToDeliver"] and \
       (response["Result"]["AssignedServerIp"] in (None, "") or response["Result"]["AssignedServerPort"] == 0):
        response["Result"]["ReadyToDeliver"] = False

    # Fix newline appended to the server IP
    if response["Result"]["AssignedServerIp"] is not None:
        response["Result"]["AssignedServerIp"] = response["Result"]["AssignedServerIp"].strip("\n")

    # Check for requested/assigned server mismatch
    if response["Result"]["ReadyToDeliver"] and \
       response["Result"]["RequestedServerGuid"] != "00000000-0000-0000-0000-000000000000" and \
       response["Result"]["AssignedServerGuid"] != response["Result"]["RequestedServerGuid"]:
        raise InvalidResponse("Requested server GUID does not matched assigned server GUID", response["Status"], response["Result"])

    # Return response
    return response["Result"]


def matchmaking_advertisement_create(session, grant, advertisement):
    response = session.api_post(endpoints.advertisement, auth=grant, data=advertisement)

    if response["Status"] == 403:
        # Owner does not match access grant user
        raise WrongUser(response["Message"], response["Status"])

    # Return result
    return response["Result"]


def matchmaking_advertisement_delete(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid advertisement GUID given")

    response = session.api_delete(endpoints.advertisement_single, guid, auth=grant)

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


def presence_access(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.presence_access, guid, auth=grant)
    except NotAuthorized as e:
        if e.message == "Access grant with matching user GUID required":
            # User does not match access grant user
            raise WrongUser(e.message, e.code)

        raise

    # Return response
    return response["Result"]


def presence_domain(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.presence_domain, guid, auth=grant)
    except NotAuthorized as e:
        if e.message == "Access grant with matching user GUID required":
            # User does not match access grant user
            raise WrongUser(e.message, e.code)

        raise

    # Return response
    return response["Result"]


def server_list(session, grant):
    response = session.api_get(endpoints.server, auth=grant)

    # Return response
    return response["Result"]


def server_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid server GUID given")

    response = session.api_get(endpoints.server_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such server
        return None

    # Return response
    return response["Result"]


def stat_overflow_list(session, grant):
    response = session.api_get(endpoints.statoverflow, auth=grant)

    # Return response
    return response["Result"]


def stat_overflow_single(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid overflow GUID given")

    response = session.api_get(endpoints.statoverflow_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such overflow
        return None

    # Return response
    return response["Result"]


def stat_overflow_transfer_from(session, grant, user, instance, overflow, amount):
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
        response = session.api_put(endpoints.statoverflow_transfer, user, instance, auth=grant, data=data)
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


def stat_overflow_transfer_to(session, grant, user, instance, overflow, amount):
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
        response = session.api_put(endpoints.statoverflow_transfer, user, instance, auth=grant, data=data)
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


def status_game_client(session):
    response = session.api_get(endpoints.status_gameclient, check=False)

    # Return response
    return response


def status_game_servers(session):
    response = session.api_get(endpoints.status_gameservers, check=False)

    # Return response
    return response


def status_services(session):
    response = session.api_get(endpoints.status_services, check=False)

    # Return response
    return response


def uniquevalues_list(session):
    response = session.api_get(endpoints.uniquevalues)

    # Return response
    return response["Result"]


def user_account(session, grant, identifier):
    # Check that we don't have a blank identifier
    if not isinstance(identifier, str) or identifier == "":
        raise ValueError("Identifier cannot be blank")

    try:
        response = session.api_get(endpoints.user, identifier, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    # Return response
    return response["Result"]


def user_clan(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_clan, guid, auth=grant)

    if response["Status"] == 404:
        # No such user/User is not in a clan
        return None

    # Return response
    return response["Result"]


def user_eula_read(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.user_eula, guid, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    # Return response
    return response["Result"]


def user_game_settings(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_settings_single, guid, auth=grant)

    if response["Status"] == 404:
        # No game settings found
        return None

    # Return response
    return response["Result"]


def user_game_settings_create(session, grant, guid, data):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_post(endpoints.user_settings_single, guid, auth=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    if response["Status"] == 201:
        # Success
        return True

    # Catch all failure
    return False


def user_game_settings_update(session, grant, guid, data):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_put(endpoints.user_settings_single, guid, auth=grant, data=data)
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


def user_game_settings_delete(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_delete(endpoints.user_settings_single, guid, auth=grant)
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


def user_guid(session, callsign):
    # Check that we don't have a blank callsign
    if not isinstance(callsign, str) or callsign == "":
        raise ValueError("Callsign cannot be blank")

    response = session.api_get(endpoints.uniquevalues_callsign, callsign)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]["UserGuid"]


def user_items(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_item, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_items_batch(session, grant, user, items):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if len(items) == 0:
        raise ValueError("List of item instance GUIDs cannot be empty")
    for guid in items:
        if not verify_guid(guid):
            raise ValueError("Invalid item instance GUID given")

    response = session.api_post(endpoints.user_item_batch, user, auth=grant, batch=items)

    if response["Status"] == 404:
        if response["Message"] == "Error retrieving batch user game items. If any item doesn't exist the batch will fail.":
            # No such achievement
            raise InvalidBatch(response["Message"], response["Status"], None)

        # No such user
        return None

    # Return response
    return response["Result"]


def user_items_broker(session, grant, user, instance, data):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid item instance GUID given")

    try:
        response = session.api_put(endpoints.user_item_broker, user, instance, auth=grant, data=data)
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


def user_items_stats(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_item_stat, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_items_stats_single(session, grant, user, instance):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid item instance GUID given")

    response = session.api_get(endpoints.user_item_stat_single, user, instance, auth=grant)

    if response["Status"] == 404:
        if response["Message"] == "No items found":
            # No such item
            return None

        # No such user
        return False

    # Return response
    return response["Result"]


def user_meteor_settings(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.user_meteor_single, guid, auth=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.message, e.code)

    # Return response
    return response["Result"]


def user_publicdata_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_publicdata_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_server(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.server_user, guid, auth=grant)

    if response["Status"] == 404:
        # No such user/user is not on a server
        return None

    # Return response
    return response["Result"]


def user_stats_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_stat_single, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def user_stats_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of user GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid user GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, batch_limit):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.user_stat_batch, auth=grant, batch=chunk)["Result"])

    # Return data set
    return data


def user_transaction(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_post(endpoints.transaction, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    if response["Status"] == 201:
        # Return response
        return response["Result"]

    # Catch all failure
    return False


def version(session):
    response = session.api_get(endpoints.version)

    # Return response
    return response["Result"]


def voice_access(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.voice_access, guid, auth=grant)

    # Return response
    return response["Result"]


def voice_info(session, grant):
    response = session.api_get(endpoints.voice_info, auth=grant)

    # Return response
    return response["Result"]


def voice_lookup(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid vivox user GUID given")

    response = session.api_get(endpoints.voice_lookup, guid, auth=grant)

    if response["Status"] == 404:
        # No such user
        return None

    # Return response
    return response["Result"]


def voice_user(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.voice_user, guid, auth=grant)

    # Return response
    return response["Result"]


def voice_channel(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid channel GUID given")

    response = session.api_get(endpoints.voice_channel, guid, auth=grant)

    # Return response
    return response["Result"]
