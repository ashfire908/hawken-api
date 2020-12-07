# -*- coding: utf-8 -*-
# Low-level API interface
# Copyright (c) 2013-2015 Andrew Hampe

import socket
import requests
from requests.auth import AuthBase
from requests.adapters import HTTPAdapter, DEFAULT_POOLSIZE, DEFAULT_RETRIES
from requests.exceptions import Timeout
import json
import hawkenapi
from hawkenapi import endpoints
from hawkenapi.endpoints import Methods
from hawkenapi.exceptions import AuthenticationFailure, NotAuthorized, InternalServerError, \
    ServiceUnavailable, WrongUser, InvalidRequest, InvalidBatch, InvalidResponse, NotAuthenticated, \
    NotAllowed, InsufficientFunds, InvalidStatTransfer, AccountBanned, AccountDeactivated, AccountLockout
from hawkenapi.util import verify_guid, chunks, BLANK_GUID

__all__ = ["ApiSession", "auth", "deauth", "achievement_list", "achievement_batch", "achievement_reward_list",
           "achievement_reward_single", "achievement_reward_batch", "achievement_user_list", "achievement_user_batch",
           "achievement_user_unlock", "antiaddiction", "currency_hawken", "currency_meteor", "events_url", "game_items",
           "game_items_single", "game_items_batch", "game_offers_list", "game_offers_single", "game_offers_batch",
           "game_offers_redeem", "game_offers_rent", "generate_advertisement_matchmaking",
           "generate_advertisement_server", "matchmaking_advertisement", "matchmaking_advertisement_create",
           "matchmaking_advertisement_delete", "presence_access", "presence_domain", "server_list", "server_single",
           "stat_overflow_list", "stat_overflow_single", "stat_overflow_transfer_from", "stat_overflow_transfer_to",
           "status", "user_transaction", "uniquevalues_list", "user_account", "user_eula_read", "user_game_settings",
           "user_game_settings_create", "user_game_settings_update", "user_game_settings_delete", "user_guid",
           "user_items", "user_items_batch", "user_items_broker", "user_items_stats", "user_items_stats_single",
           "user_meteor_settings", "user_publicdata_single", "user_server", "user_stats_single", "user_stats_batch",
           "version", "voice_access", "voice_info", "voice_lookup", "voice_user", "voice_channel", "bundle_list",
           "bundle_single", "bundle_batch", "user_publicdata_batch"]

BATCH_LIMIT = 200


# Auth handler
class MeteorAuth(AuthBase):
    def __init__(self, grant):
        self.grant = str(grant)

    def __call__(self, r):
        r.headers["Authorization"] = "Basic {0}".format(self.grant)
        return r


# Session
class ApiSession(requests.Session):
    def __init__(self, host=None, stack=None, scheme=None, timeout=None, pool_connections=DEFAULT_POOLSIZE, pool_maxsize=DEFAULT_POOLSIZE, max_retries=DEFAULT_RETRIES):
        super().__init__()

        # Set defaults
        self._host = "v2.services.live.hawken.meteor-ent.com"
        self._stack = None
        self._scheme = "https"

        # Set the user agent
        self.headers["User-Agent"] = "HawkenApi/{0}".format(hawkenapi.__version__)

        # Set the host
        if host:
            self.host = host
        elif stack:
            self.stack = stack

        # Set the scheme
        if scheme:
            self.scheme = scheme

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

    def build_request(self, method, endpoint, *args, grant=None, data=None, batch=None, **fields):
        headers = {}

        # Verify endpoint support
        if method not in endpoint.methods:
            raise ValueError("Endpoint does not support {0} method".format(method))
        if data and method == Methods.get:
            raise ValueError("The {0} method does not take a request body".format(method))
        if not grant and endpoint.flags.authrequired:
            raise ValueError("Endpoint requires an access grant")

        # Get the url
        url = self.format_endpoint(endpoint, *args)

        # Handle auth
        if grant:
            grant = MeteorAuth(grant)

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
        return self.prepare_request(requests.Request(method, url, headers=headers, data=data, params=endpoint.format_fields(**fields), auth=grant))

    def perform_request(self, request, check=True):
        try:
            response = self.send(request, timeout=self.timeout)
        except socket.timeout:
            raise Timeout(request=request)

        # Check for HTTP errors
        if response.status_code != requests.codes.ok:
            if response.status_code == requests.codes.service_unavailable:
                raise ServiceUnavailable(response)
            if response.status_code == requests.codes.internal_server_error:
                raise InternalServerError(response)
            if response.status_code == requests.codes.bad_request:
                raise InvalidRequest(response)

            response.raise_for_status()

        # Parse inner status
        status = response.json()["Status"]

        # Check for server errors
        if status == requests.codes.internal_server_error:
            raise InternalServerError(response)

        if check:
            # Check for authentication errors
            if status == requests.codes.unauthorized:
                if NotAuthenticated.detect(response):
                    # Missing authentication
                    raise NotAuthenticated(response)
                if NotAllowed.detect(response):
                    # Denied access
                    raise NotAllowed(response)

                # General authentication error
                raise NotAuthorized(response)

            # Check for invalid request errors
            if status == requests.codes.bad_request:
                if InvalidBatch.detect(response):
                    # Invalid batch
                    raise InvalidBatch(response)

                # General invalid request
                raise InvalidRequest(response)

        # Return HTTP response
        return response

    def api_call(self, method, endpoint, *args, grant=None, data=None, batch=None, check=True, **fields):
        request = self.build_request(method, endpoint, *args, grant=grant, data=data, batch=batch, **fields)
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
    reply = response.json()

    if reply["Status"] == requests.codes.ok:
        # Return response
        return reply["Result"]

    if reply["Status"] == requests.codes.unauthorized and AccountDeactivated.detect(response):
        # Account deactivated
        raise AccountDeactivated(response)

    if reply["Status"] == requests.codes.forbidden:
        if AccountLockout.detect(response):
            # Account locked out
            raise AccountLockout(response)

        # Account banned
        raise AccountBanned(response)

    if reply["Status"] in (requests.codes.not_found, requests.codes.invalid_request, requests.codes.unauthorized):
        # Rejected authentication (No such user/Blank password/Incorrect password)
        raise AuthenticationFailure(response)

    # Catch all failure
    return False


def deauth(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    data = {"AccessGrant": grant}

    try:
        response = session.api_put(endpoints.user_accessgrant, guid, grant=grant, data=data, check=False)
    except NotAuthorized as e:
        if e.error == NotAuthorized.Error.revoked:
            # Already revoked
            return True

        raise

    if response.json()["Status"] == requests.codes.ok:
        # Success
        return True

    # Catch all failure
    return False


def achievement_list(session, grant, countrycode=None):
    response = session.api_get(endpoints.achievement, grant=grant, countrycode=countrycode)

    # Return the achievement list
    return response.json()["Result"]


def achievement_batch(session, grant, guids, countrycode=None):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of achievement GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, BATCH_LIMIT):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.achievement_batch, grant=grant, batch=chunk, countrycode=countrycode).json()["Result"])

    # Return data set
    return data


def achievement_reward_list(session, grant, countrycode=None):
    response = session.api_get(endpoints.achievement_reward, grant=grant, countrycode=countrycode)

    # Return response
    return response.json()["Result"]


def achievement_reward_single(session, grant, guid, countrycode=None):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid achievement reward GUID given")

    response = session.api_get(endpoints.achievement_reward_single, guid, grant=grant, countrycode=countrycode)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such reward
        return None

    # Return response
    return reply["Result"]


def achievement_reward_batch(session, grant, guids, countrycode=None):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of achievement reward GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement reward GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, BATCH_LIMIT):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.achievement_reward_batch, grant=grant, batch=chunk, countrycode=countrycode).json()["Result"])

    # Return data set
    return data


def achievement_user_list(session, grant, guid, countrycode=None):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.achievement_user, guid, grant=grant, countrycode=countrycode)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "User not found":
            # No such user
            return None

        # No achievements for the user
        return []

    # Return response
    return reply["Result"]


def achievement_user_batch(session, grant, user, achievements, countrycode=None):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if len(achievements) == 0:
        raise ValueError("List of achievement GUIDs cannot be empty")
    for guid in achievements:
        if not verify_guid(guid):
            raise ValueError("Invalid achievement GUID given")

    response = session.api_post(endpoints.achievement_user_query, user, grant=grant, batch=achievements, countrycode=countrycode)
    reply = response.json()

    if reply["Status"] == requests.codes.not_fund:
        if reply["Message"] == "Error retrieving batch items.":
            # No such achievement
            raise InvalidBatch(response)

        # No such user
        return None

    # Return response
    return reply["Result"]


def achievement_user_unlock(session, grant, user, achievement):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(user):
        raise ValueError("Invalid achievement GUID given")

    response = session.api_post(endpoints.achievement_user_client, user, achievement, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.forbidden:
        if reply["Message"] == "Requesting access grant's user GUID must match user GUID parameter":
            # User does not match access grant user
            raise WrongUser(response)

        if reply["Message"] == "Achievement is already redeemed":
            # Achievement already unlocked
            return False

        # Can't be unlocked from client
        raise InvalidRequest(response)

    if reply["Status"] == requests.codes.not_found:
        # No such achievement
        return None

    # Success
    return True


def antiaddiction(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.antiaddiction, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.ok:
        # No such user
        return None

    # Return response
    return reply["Result"]


def bundle_list(session, grant):
    response = session.api_get(endpoints.bundle, grant=grant)

    # Return response
    return response.json()["Result"]


def bundle_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid bundle GUID given")

    response = session.api_get(endpoints.bundle_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such bundle
        return None

    # Return response
    return reply["Result"]


def bundle_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of bundle GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid bundle GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, BATCH_LIMIT):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.bundle, grant=grant, batch=chunk).json()["Result"])

    # Return data set
    return data


def currency_hawken(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.currency_game, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def currency_meteor(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.currency_meteor, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def events_url(session):
    response = session.api_get(endpoints.eventsurl)

    # Return response
    return response.json()["Result"]


def game_items(session, grant):
    response = session.api_get(endpoints.item, grant=grant)

    # Return response
    return response.json()["Result"]


def game_items_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid item GUID given")

    response = session.api_get(endpoints.item_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such item
        return None

    # Return response
    return reply["Result"]


def game_items_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of item GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid item GUID given")

    response = session.api_post(endpoints.item_batch, grant=grant, batch=guids)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such item
        raise InvalidBatch(response)

    # Return response
    return reply["Result"]


def game_offers_list(session, grant):
    response = session.api_get(endpoints.offer, grant=grant)

    # Return response
    return response.json()["Result"]


def game_offers_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid offer GUID given")

    response = session.api_get(endpoints.offer_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such offer
        return None

    # Return response
    return reply["Result"]


def game_offers_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of offer GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid offer GUID given")

    response = session.api_post(endpoints.offer_batch, grant=grant, batch=guids)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such offer
        raise InvalidBatch(response)

    # Return response
    return reply["Result"]


def game_offers_redeem(session, grant, user, offer, currency, transaction, parent=None):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(offer):
        raise ValueError("Invalid offer GUID given")
    if currency not in ("HP", "MP"):
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
        response = session.api_post(endpoints.offer_redeemer, user, offer, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "No valid transaction for user {0} with id {1}".format(user, transaction):
            # Invalid transaction
            raise InvalidRequest(response)

        if reply["Message"] == "No items found":
            # No such parent item
            raise InvalidRequest(response)

        # No such offer
        return None

    if reply["Status"] == requests.codes.forbidden:
        # Offer is disabled
        raise InvalidRequest(response)

    if reply["Status"] == requests.codes.precondition_failed:
        # Not enough currency
        raise InsufficientFunds(response)

    # Return response
    return reply["Result"]


def game_offers_rent(session, grant, user, offer, currency, transaction, parent=None):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(offer):
        raise ValueError("Invalid offer GUID given")
    if currency not in ("HP", "MP"):
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
        response = session.api_post(endpoints.offer_renter, user, offer, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "No valid transaction for user {0} with id {1}".format(user, transaction):
            # Invalid transaction
            raise InvalidRequest(response)

        if reply["Message"] == "No items found":
            # No such parent item
            raise InvalidRequest(response)

        # No such offer
        return None

    if reply["Status"] == requests.codes.precondition_failed:
        # Not enough currency
        raise InsufficientFunds(response)

    # Return response
    return reply["Result"]


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

    response = session.api_get(endpoints.advertisement_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such advertisement
        return None

    # Fix incomplete request marked as ready
    if reply["Result"]["ReadyToDeliver"] and \
       (reply["Result"]["AssignedServerIp"] in (None, "") or reply["Result"]["AssignedServerPort"] == 0):
        reply["Result"]["ReadyToDeliver"] = False

    # Fix newline appended to the server IP
    if reply["Result"]["AssignedServerIp"] is not None:
        reply["Result"]["AssignedServerIp"] = reply["Result"]["AssignedServerIp"].strip("\n")

    # Check for requested/assigned server mismatch
    if reply["Result"]["ReadyToDeliver"] and \
       reply["Result"]["RequestedServerGuid"] != BLANK_GUID and \
       reply["Result"]["AssignedServerGuid"] != reply["Result"]["RequestedServerGuid"]:
        raise InvalidResponse(response, "Requested server GUID does not matched assigned server GUID")

    # Return response
    return reply["Result"]


def matchmaking_advertisement_create(session, grant, advertisement):
    response = session.api_post(endpoints.advertisement, grant=grant, data=advertisement)
    reply = response.json()

    if reply["Status"] == requests.codes.forbidden:
        # Owner does not match access grant user
        raise WrongUser(response)

    # Return result
    return reply["Result"]


def matchmaking_advertisement_delete(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid advertisement GUID given")

    response = session.api_delete(endpoints.advertisement_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.forbidden:
        # Owner does not match access grant user
        raise WrongUser(response)

    if reply["Status"] == requests.codes.not_found:
        # No such advertisement
        return None

    if reply["Status"] == requests.codes.ok:
        # Success
        return True

    # Catch all failure
    return False


def presence_access(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.presence_access, guid, grant=grant)
    except NotAuthorized as e:
        if e.message == "Access grant with matching user GUID required":
            # User does not match access grant user
            raise WrongUser(e.response)

        raise

    # Return response
    return response.json()["Result"]


def presence_domain(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.presence_domain, guid, grant=grant)
    except NotAuthorized as e:
        if e.message == "Access grant with matching user GUID required":
            # User does not match access grant user
            raise WrongUser(e.response)

        raise

    # Return response
    return response.json()["Result"]


def server_list(session, grant):
    response = session.api_get(endpoints.server, grant=grant)

    # Return response
    return response.json()["Result"]


def server_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid server GUID given")

    response = session.api_get(endpoints.server_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such server
        return None

    # Return response
    return reply["Result"]


def stat_overflow_list(session, grant):
    response = session.api_get(endpoints.statoverflow, grant=grant)

    # Return response
    return response.json()["Result"]


def stat_overflow_single(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid overflow GUID given")

    response = session.api_get(endpoints.statoverflow_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such overflow
        return None

    # Return response
    return reply["Result"]


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
        response = session.api_put(endpoints.statoverflow_transfer, user, instance, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)
    except InvalidRequest as e:
        if InvalidStatTransfer.detect(e.response):
            # Invalid stat transfer operation
            raise InvalidStatTransfer(e.response)

        raise

    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "{0} not found".format(overflow):
            # No such overflow
            raise InvalidRequest(response)

        # No such item
        return None

    if reply["Status"] == requests.codes.precondition_failed:
        # Not enough currency
        raise InsufficientFunds(response)

    if reply["Status"] == requests.codes.ok:
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
        response = session.api_put(endpoints.statoverflow_transfer, user, instance, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)
    except InvalidRequest as e:
        if InvalidStatTransfer.detect(e.response):
            # Invalid stat transfer operation
            raise InvalidStatTransfer(e.response)

        raise

    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "{0} not found".format(overflow):
            # No such overflow
            raise InvalidRequest(response)

        # No such item
        return None

    if reply["Status"] == requests.codes.precondition_failed:
        # Not enough currency
        raise InsufficientFunds(response)

    if reply["Status"] == requests.codes.ok:
        # Success
        return True

    # Catch all failure
    return False


def status(session, name):
    try:
        response = session.api_get(endpoints.status, name, check=False)
    except InternalServerError as e:
        # Status uses internal server error as a status code
        if e.response.status_code != requests.codes.ok:
            raise

        response = e.response

    # Return response
    return response.json()


def uniquevalues_list(session):
    response = session.api_get(endpoints.uniquevalues)

    # Return response
    return response.json()["Result"]


def user_account(session, grant, identifier):
    # Check that we don't have a blank identifier
    if not isinstance(identifier, str) or identifier == "":
        raise ValueError("Identifier cannot be blank")

    try:
        response = session.api_get(endpoints.user, identifier, grant=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    # Return response
    return response.json()["Result"]


def user_eula_read(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.user_eula, guid, grant=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    # Return response
    return response.json()["Result"]


def user_game_settings(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_settings_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No game settings found
        return None

    # Return response
    return reply["Result"]


def user_game_settings_create(session, grant, guid, data):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_post(endpoints.user_settings_single, guid, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    if response.json()["Status"] == requests.codes.created:
        # Success
        return True

    # Catch all failure
    return False


def user_game_settings_update(session, grant, guid, data):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_put(endpoints.user_settings_single, guid, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No game settings exists
        return None

    if reply["Status"] == requests.codes.ok:
        # Success
        return True

    # Catch all failure
    return False


def user_game_settings_delete(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_delete(endpoints.user_settings_single, guid, grant=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No game settings exists
        return None

    if reply["Status"] == requests.codes.ok:
        # Success
        return True

    # Catch all failure
    return False


def user_guid(session, callsign):
    # Check that we don't have a blank callsign
    if not isinstance(callsign, str) or callsign == "":
        raise ValueError("Callsign cannot be blank")

    response = session.api_get(endpoints.uniquevalues_callsign, callsign)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]["UserGuid"]


def user_items(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_item, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def user_items_batch(session, grant, user, items):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if len(items) == 0:
        raise ValueError("List of item instance GUIDs cannot be empty")
    for guid in items:
        if not verify_guid(guid):
            raise ValueError("Invalid item instance GUID given")

    response = session.api_post(endpoints.user_item_batch, user, grant=grant, batch=items)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "Error retrieving batch user game items. If any item doesn't exist the batch will fail.":
            # No such achievement
            raise InvalidBatch(response)

        # No such user
        return None

    # Return response
    return reply["Result"]


def user_items_broker(session, grant, user, instance, data):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid item instance GUID given")

    try:
        response = session.api_put(endpoints.user_item_broker, user, instance, grant=grant, data=data)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    reply = response.json()

    if reply["Status"] == requests.codes.forbidden:
        # Action not allowed
        raise NotAllowed(response)

    if reply["Status"] == requests.codes.not_found:
        # No such item
        return None

    if reply["Status"] == requests.codes.ok:
        # Success
        return True

    # Catch all failure
    return False


def user_items_stats(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_item_stat, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def user_items_stats_single(session, grant, user, instance):
    # Validate the guids given
    if not verify_guid(user):
        raise ValueError("Invalid user GUID given")
    if not verify_guid(instance):
        raise ValueError("Invalid item instance GUID given")

    response = session.api_get(endpoints.user_item_stat_single, user, instance, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        if reply["Message"] == "No items found":
            # No such item
            return None

        # No such user
        return False

    # Return response
    return reply["Result"]


def user_meteor_settings(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    try:
        response = session.api_get(endpoints.user_meteor_single, guid, grant=grant)
    except NotAllowed as e:
        # User does not match access grant user
        raise WrongUser(e.response)

    # Return response
    return response.json()["Result"]


def user_publicdata_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of user GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid user GUID given")

    data = []
    # Perform a chunked request
    for chunk in chunks(guids, BATCH_LIMIT):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.user_publicdata_batch, grant=grant, batch=chunk).json()["Result"])

    # Remove empty entries
    data = [user for user in data if len(user) > 1]

    # Return data set
    return data


def user_publicdata_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_publicdata_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def user_server(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.server_user, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user/user is not on a server
        return None

    # Return response
    return reply["Result"]


def user_stats_single(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.user_stat_single, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def user_stats_batch(session, grant, guids):
    # Validate the guids given
    if len(guids) == 0:
        raise ValueError("List of user GUIDs cannot be empty")
    for guid in guids:
        if not verify_guid(guid):
            raise ValueError("Invalid user GUID given")

    data = []
    # Perform a chunked request
    # BUG: API breaks at anything more than 100 users at a time
    for chunk in chunks(guids, 100):
        # Retrieve a chunk and add the response to the data set
        data.extend(session.api_get(endpoints.user_stat_batch, grant=grant, batch=chunk).json()["Result"])

    # Return data set
    return data


def user_transaction(session, grant, guid):
    # Verify guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_post(endpoints.transaction, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    if reply["Status"] == requests.codes.created:
        # Return response
        return reply["Result"]

    # Catch all failure
    return False


def version(session):
    response = session.api_get(endpoints.version)

    # Return response
    return response.json()["Result"]


def voice_access(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.voice_access, guid, grant=grant)

    # Return response
    return response.json()["Result"]


def voice_info(session, grant):
    response = session.api_get(endpoints.voice_info, grant=grant)

    # Return response
    return response.json()["Result"]


def voice_lookup(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid vivox user GUID given")

    response = session.api_get(endpoints.voice_lookup, guid, grant=grant)
    reply = response.json()

    if reply["Status"] == requests.codes.not_found:
        # No such user
        return None

    # Return response
    return reply["Result"]


def voice_user(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid user GUID given")

    response = session.api_get(endpoints.voice_user, guid, grant=grant)

    # Return response
    return response.json()["Result"]


def voice_channel(session, grant, guid):
    # Validate the guid given
    if not verify_guid(guid):
        raise ValueError("Invalid channel GUID given")

    response = session.api_get(endpoints.voice_channel, guid, grant=grant)

    # Return response
    return response.json()["Result"]
