# -*- coding: utf-8 -*-
# High-level API client
# Copyright (c) 2013-2017 Andrew Hampe

from datetime import datetime
from functools import wraps
import logging
from hawkenapi.cache import CacheWrapper
from hawkenapi.endpoints import RequestType
from hawkenapi.exceptions import NotAuthorized, InvalidBatch
from hawkenapi.interface import *
from hawkenapi.util import JWTParser

__all__ = ["AccessGrant", "Client"]


# Setup logging
logger = logging.getLogger(__name__)


# Decorators
def require_auth(func):
    @wraps(func)
    def auth_handler(self, *args, **kwargs):
        reauthed = False

        # Check if we have authenticated
        if not self.authed:
            logger.error("Auth-required request made but no authentication has been performed.")
            raise ValueError("Client has not authenticated to the API")
        # Check if the grant has expired
        elif self.grant.is_expired:
            logger.info("Automatically authenticating [expired]")
            self.reauth()
            reauthed = True

        try:
            return func(self, *args, **kwargs)
        except NotAuthorized as e:
            # Only reauth if the grant expired
            if e.error == NotAuthorized.Error.expired and not reauthed:
                logger.info("Automatically authenticating [reauth] ([%i] %s)", e.status, e.message)
                self.reauth()
                return func(self, *args, **kwargs)

            raise
    return auth_handler


# Access grant
class AccessGrant:
    def __init__(self, token):
        self.token = token

        # Parse the token
        jwt = JWTParser(self.token)

        # Set data
        self.token_id = jwt.payload["jti"]
        self.user = jwt.payload["prn"]
        self.expires = jwt.payload["exp"]
        self.not_before = jwt.payload["nbf"]

    @property
    def is_expired(self):
        return datetime.now() > self.expires

    @property
    def is_not_ready(self):
        return self.not_before > datetime.now()

    @property
    def is_valid(self):
        return self.not_before > datetime.now() > self.expires

    def __str__(self):
        return self.token


# Client
class Client:
    def __init__(self, session=None, cache=None):
        if session:
            self.session = session
        else:
            self.session = ApiSession()

        # Init auth data
        self._grant = None
        self.identifier = None
        self.password = None

        self.cache = cache

    @property
    def grant(self):
        return self._grant

    @grant.setter
    def grant(self, value):
        self._grant = AccessGrant(value)

    @grant.deleter
    def grant(self):
        self._grant = None

    @property
    def guid(self):
        try:
            return self._grant.user
        except AttributeError:
            return None

    @property
    def authed(self):
        return self._grant is not None

    @CacheWrapper.no_cache
    def login(self, identifier, password):
        # Auth to the API
        grant = storm_auth(self.session, identifier, password)

        if grant:
            # Save the user/password
            self.identifier = identifier
            self.password = password

            # Set the grant token
            self.grant = grant

            return True
        return False

    @CacheWrapper.no_cache
    @require_auth
    def logout(self):
        try:
            result = revoke_auth(self.session, str(self.grant), self.guid)
        finally:
            # Reset the auth info
            del self.grant
            self.identifier = None
            self.password = None

        return result

    def reauth(self):
        return self.login(self.identifier, self.password)

    @CacheWrapper("achievements_list", expiry="game")
    @require_auth
    @RequestType.set(RequestType.guid_list)
    def get_achievements_list(self, countrycode=None):
        return achievements_list(self.session, self.grant, countrycode=countrycode)

    @CacheWrapper("achievements", key="AchievementGuid", expiry="game")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_achievements(self, achievement, countrycode=None):
        if isinstance(achievement, str):
            # Emulate a single-type request
            try:
                data = achievements_batch(self.session, self.grant, [achievement], countrycode=countrycode)
            except InvalidBatch:
                return None

            return data[0]

        return achievements_batch(self.session, self.grant, achievement, countrycode=countrycode)

    @CacheWrapper("achievement_rewards_list", expiry="game")
    @require_auth
    @RequestType.set(RequestType.guid_list)
    def get_achievement_rewards_list(self, countrycode=None):
        return achievement_rewards_list(self.session, self.grant, countrycode=countrycode)

    @CacheWrapper("achievement_rewards", key="Guid", expiry="game")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_achievement_rewards(self, achievement, countrycode=None):
        if isinstance(achievement, str):
            return achievement_rewards_single(self.session, self.grant, achievement, countrycode=countrycode)

        return achievement_rewards_batch(self.session, self.grant, achievement, countrycode=countrycode)

    @CacheWrapper("user_achievements_list", expiry="stats")
    @require_auth
    @RequestType.set(RequestType.guid_list)
    def get_user_achievements_list(self, user, countrycode=None):
        return user_achievements_list(self.session, self.grant, user, countrycode=countrycode)

    @CacheWrapper("user_achievements", key="AchievementGuid", expiry="stats")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_user_achievements(self, user, achievement, countrycode=None):
        if isinstance(achievement, str):
            # Emulate a single-type request
            try:
                data = user_achievements_batch(self.session, self.grant, user, [achievement], countrycode=countrycode)
            except InvalidBatch:
                return None

            return data[0]

        return user_achievements_batch(self.session, self.grant, user, achievement, countrycode=countrycode)

    @CacheWrapper.no_cache
    @require_auth
    def unlock_achievement(self, achievement):
        return user_achievements_unlock(self.session, self.grant, self.guid, achievement)

    @CacheWrapper("antiaddiction", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_antiaddition(self, user):
        return antiaddiction(self.session, self.grant, user)

    @CacheWrapper("bundles_list", expiry="game")
    @require_auth
    @RequestType.set(RequestType.guid_list)
    def get_bundle_list(self):
        return bundle_list(self.session, self.grant)

    @CacheWrapper("bundles", key="Guid", expiry="game")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_bundle(self, bundle):
        if isinstance(bundle, str):
            return bundle_single(self.session, self.grant, bundle)

        return bundle_batch(self.session, self.grant, bundle)

    @CacheWrapper("hawken_credits", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_hawken_credits(self, user):
        return currency_hawken(self.session, self.grant, user)

    @CacheWrapper("meteor_credits", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_meteor_credits(self, user):
        return currency_meteor(self.session, self.grant, user)

    @CacheWrapper("events_url", expiry="globals")
    @RequestType.set(RequestType.single_item)
    def get_events_url(self):
        return events_url(self.session)

    @CacheWrapper("game_items_list", list_identifier="game_items", key="Guid", expiry="game")
    @require_auth
    @RequestType.set(RequestType.item_list)
    def get_game_items_list(self):
        return game_items(self.session, self.grant)

    @CacheWrapper("game_items", key="Guid", expiry="game")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_game_items(self, item):
        if isinstance(item, str):
            return game_items_single(self.session, self.grant, item)

        return game_items_batch(self.session, self.grant, item)

    @CacheWrapper("game_offers_list", expiry="game")
    @require_auth
    @RequestType.set(RequestType.guid_list)
    def get_game_offers_list(self):
        return game_offers_list(self.session, self.grant)

    @CacheWrapper("game_offers", key="GameOfferGuid", expiry="game")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_game_offers(self, offer):
        if isinstance(offer, str):
            return game_offers_single(self.session, self.grant, offer)

        return game_offers_batch(self.session, self.grant, offer)

    @CacheWrapper.no_cache
    @require_auth
    def redeem_game_offer(self, offer, currency, transaction, parent=None):
        return game_offers_redeem(self.session, self.grant, self.guid, offer, currency, transaction, parent=parent)

    @CacheWrapper.no_cache
    @require_auth
    def rent_game_offer(self, offer, currency, transaction, parent=None):
        return game_offers_rent(self.session, self.grant, self.guid, offer, currency, transaction, parent=parent)

    @CacheWrapper.no_cache
    @require_auth
    def get_advertisement(self, advertisement):
        return matchmaking_advertisement(self.session, self.grant, advertisement)

    @CacheWrapper.no_cache
    @require_auth
    def create_matchmaking_advertisement(self, gameversion, region, users, gametype=None, party=None):
        advertisement = generate_advertisement_matchmaking(gameversion, region, self.guid, users, gametype, party)

        return matchmaking_advertisement_create(self.session, self.grant, advertisement)

    @CacheWrapper.no_cache
    @require_auth
    def create_server_advertisement(self, gameversion, region, server, users, party=None):
        advertisement = generate_advertisement_server(gameversion, region, server, self.guid, users, party)

        return matchmaking_advertisement_create(self.session, self.grant, advertisement)

    @CacheWrapper.no_cache
    @require_auth
    def delete_advertisement(self, advertisement):
        return matchmaking_advertisement_delete(self.session, self.grant, advertisement)

    @CacheWrapper.no_cache
    @require_auth
    def get_presence_access(self):
        return presence_access(self.session, self.grant, self.guid)

    @CacheWrapper.no_cache
    @require_auth
    def get_presence_domain(self):
        return presence_domain(self.session, self.grant, self.guid)

    @CacheWrapper("server_list", list_identifier="server", key="Guid", expiry="server")
    @require_auth
    @RequestType.set(RequestType.item_list)
    def get_server_list(self):
        return server_list(self.session, self.grant)

    @CacheWrapper("server", expiry="server")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_server(self, server):
        return server_single(self.session, self.grant, server)

    @require_auth
    def get_server_by_name(self, name, **kwargs):
        servers = []
        name = name.lower()
        for server in self.get_server_list(**kwargs):
            if server["ServerName"].lower() == name:
                servers.append(server)

        return servers

    @CacheWrapper("stat_overflow_list", expiry="game")
    @require_auth
    @RequestType.set(RequestType.guid_list)
    def get_stat_overflow_list(self):
        return stat_overflow_list(self.session, self.grant)

    @CacheWrapper("stat_overflow", expiry="game")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_stat_overflow(self, overflow):
        return stat_overflow_single(self.session, self.grant, overflow)

    @CacheWrapper.no_cache
    @require_auth
    def transfer_stat_overflow_from_item(self, item, overflow, amount):
        return stat_overflow_transfer_from(self.session, self.grant, self.guid, item, overflow, amount)

    @CacheWrapper.no_cache
    @require_auth
    def transfer_stat_overflow_to_item(self, item, overflow, amount):
        return stat_overflow_transfer_to(self.session, self.grant, self.guid, item, overflow, amount)

    @CacheWrapper("game_client_status", expiry="status")
    @RequestType.set(RequestType.single_item)
    def get_game_client_status(self):
        return status(self.session, "game_client")

    @CacheWrapper("game_servers_status", expiry="status")
    @RequestType.set(RequestType.single_item)
    def get_game_servers_status(self):
        return status(self.session, "game_servers")

    @CacheWrapper("services_status", expiry="status")
    @RequestType.set(RequestType.single_item)
    def get_services_status(self):
        return status(self.session, "services")

    @CacheWrapper("website_status", expiry="status")
    @RequestType.set(RequestType.single_item)
    def get_website_status(self):
        return status(self.session, "website")

    @CacheWrapper("user", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_user(self, identifier):
        return user_account(self.session, self.grant, identifier)

    @CacheWrapper("user_eula", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_eula_status(self, user):
        return user_eula_read(self.session, self.grant, user)

    @CacheWrapper("user_game_settings", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_user_game_settings(self, user):
        return user_game_settings(self.session, self.grant, user)

    @CacheWrapper.no_cache
    @require_auth
    def create_user_game_settings(self, settings):
        return user_game_settings_create(self.session, self.grant, self.guid, settings)

    @CacheWrapper.no_cache
    @require_auth
    def update_user_game_settings(self, settings):
        return user_game_settings_update(self.session, self.grant, self.guid, settings)

    @CacheWrapper.no_cache
    @require_auth
    def delete_user_game_settings(self):
        return user_game_settings_delete(self.session, self.grant, self.guid)

    @CacheWrapper("user_guid", expiry="persistent")
    @RequestType.set(RequestType.single_item)
    def get_user_guid(self, callsign):
        return user_guid(self.session, callsign)

    @CacheWrapper("user_items_list", list_identifier="user_items", key="UserGameItemGuid", expiry="user")
    @require_auth
    @RequestType.set(RequestType.item_list)
    def get_user_items_list(self, user):
        return user_items(self.session, self.grant, user)

    @CacheWrapper("user_items", key="UserGameItemGuid", expiry="user")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_user_items(self, user, item):
        if isinstance(item, str):
            # Emulate a single-type request
            try:
                data = user_items_batch(self.session, self.grant, user, [item])
            except InvalidBatch:
                return None

            if data:
                return data[0]

            return data

        return user_items_batch(self.session, self.grant, user, item)

    @CacheWrapper.no_cache
    @require_auth
    def update_user_item(self, item, data):
        return user_items_broker(self.session, self.grant, self.guid, item, data)

    @CacheWrapper("user_item_stats_list", list_identifier="user_item_stats", key="UserGameItemGuid", expiry="stats")
    @require_auth
    @RequestType.set(RequestType.item_list)
    def get_user_items_stats_list(self, user):
        return user_items_stats(self.session, self.grant, user)

    @CacheWrapper("user_item_stats", expiry="stats")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_user_item_stats(self, user, item):
        return user_items_stats_single(self.session, self.grant, user, item)

    @CacheWrapper("user_meteor_settings", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_meteor_settings(self, user):
        return user_meteor_settings(self.session, self.grant, user)

    @CacheWrapper("user_legacy_data", key="Guid", expiry="persistent")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_user_legacy_data(self, user):
        if isinstance(user, str):
            data = user_publicdata_single(self.session, self.grant, user)

            # Keep single item interface compatible with batch item caching
            if data is not None:
                data["Guid"] = user

            return data

        return user_publicdata_batch(self.session, self.grant, user)

    @require_auth
    def get_user_callsign(self, user, **kwargs):
        response = self.get_user_legacy_data(user, **kwargs)

        if response is not None:
            if isinstance(user, str):
                # Some users don't have a callsign
                return response.get("UniqueCaseInsensitive_Callsign", None)

            # Create map of callsigns
            return {item["Guid"]: item.get("UniqueCaseInsensitive_Callsign", None) for item in response}

        return None

    @CacheWrapper("user_server", expiry="server")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_user_server(self, user):
        return user_server(self.session, self.grant, user)

    @CacheWrapper("stats", key="Guid", expiry="stats")
    @require_auth
    @RequestType.set(RequestType.batch_item)
    def get_user_stats(self, user):
        if isinstance(user, str):
            return user_stats_single(self.session, self.grant, user)

        return user_stats_batch(self.session, self.grant, user)

    @CacheWrapper.no_cache
    @require_auth
    def create_transaction(self):
        return user_transaction(self.session, self.grant, self.guid)

    @CacheWrapper("version", expiry="globals")
    @RequestType.set(RequestType.single_item)
    def get_version(self):
        return version(self.session)

    @CacheWrapper.no_cache
    @require_auth
    def get_voice_access(self):
        return voice_access(self.session, self.grant, self.guid)

    @CacheWrapper("voice_info", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_voice_info(self):
        return voice_info(self.session, self.grant)

    @CacheWrapper("voice_user_id", expiry="user")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_voice_user_id(self, user):
        return voice_user(self.session, self.grant, user)

    @CacheWrapper("voice_channel", expiry="server")
    @require_auth
    @RequestType.set(RequestType.single_item)
    def get_voice_channel(self, channel):
        return voice_channel(self.session, self.grant, channel)
