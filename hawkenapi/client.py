# -*- coding: utf-8 -*-
# High-level API Client

from datetime import datetime
import logging
from hawkenapi.interface import *
from hawkenapi.exceptions import NotAuthenticated, NotAuthorized, InvalidBatch
from hawkenapi.util import JWTParser

__all__ = ["AccessGrant", "Client"]


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
            self.reauth()

        try:
            response = f(self, *args, **kwargs)
        except NotAuthorized as e:
            # Only reauth if the grant expired
            if e.expired:
                logger.info("Automatically authenticating [reauth] ([{0}] {1})".format(e.code, e.message))
                self.reauth()
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
    def __init__(self, **kwargs):
        self.session = Session(**kwargs)

        # Init auth data
        self._grant = None
        self.identifier = None
        self.password = None


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

    def login(self, identifier, password):
        # Auth to the API
        grant = auth(self.session, identifier, password)

        if grant:
            # Save the user/password
            self.identifier = identifier
            self.password = password

            # Set the grant token
            self.grant = grant

            return True
        return False

    @require_auth
    def logout(self):
        try:
            result = deauth(self.session, str(self.grant), self.guid)
        finally:
            # Reset the auth info
            del self.grant
            self.identifier = None
            self.password = None

        return result

    def reauth(self):
        return self.login(self.identifier, self.password)

    @require_auth
    def get_achievements_list(self, countrycode=None):
        return achievement_list(self.session, self.grant, countrycode=countrycode)

    @require_auth
    def get_achievements(self, achievement, countrycode=None):
        if isinstance(achievement, str):
            # Emulate a single-type request
            try:
                data = achievement_batch(self.session, self.grant, [achievement], countrycode=countrycode)
            except InvalidBatch:
                return None

            return data[0]

        return achievement_batch(self.session, self.grant, achievement, countrycode=countrycode)

    @require_auth
    def get_achievement_rewards_list(self, countrycode=None):
        return achievement_reward_list(self.session, self.grant, countrycode=countrycode)

    @require_auth
    def get_achievement_rewards(self, achievement, countrycode=None):
        if isinstance(achievement, str):
            return achievement_reward_single(self.session, self.grant, achievement, countrycode=countrycode)

        return achievement_reward_batch(self.session, self.grant, achievement, countrycode=countrycode)

    @require_auth
    def get_user_achievements_list(self, user):
        return achievement_user_list(self.session, self.grant, user)

    @require_auth
    def get_user_achievements(self, user, achievement):
        if isinstance(achievement, str):
            # Emulate a single-type request
            try:
                data = achievement_user_batch(self.session, self.grant, user, [achievement])
            except InvalidBatch:
                return None

            if data:
                return data[0]

            return data

        return achievement_user_batch(self.session, self.grant, user, achievement)

    @require_auth
    def unlock_achievement(self, achievement):
        return achievement_user_unlock(self.session, self.grant, self.guid, achievement)

    @require_auth
    def get_antiaddition(self, user):
        return antiaddiction(self.session, self.grant, user)

    @require_auth
    def get_clan_list(self, tag=None, name=None):
        return clan_list(self.session, self.grant, tag=tag, name=name)

    @require_auth
    def get_clan(self, clan):
        return clan_single(self.session, self.grant, clan)

    @require_auth
    def get_clan_users(self, clan):
        return clan_users(self.session, self.grant, clan)

    @require_auth
    def get_hawken_credits(self, user):
        return currency_hawken(self.session, self.grant, user)

    @require_auth
    def get_meteor_credits(self, user):
        return currency_meteor(self.session, self.grant, user)

    def get_events_url(self):
        return events_url(self.session)

    @require_auth
    def get_game_items_list(self):
        return game_items(self.session, self.grant)

    @require_auth
    def get_game_items(self, item):
        if isinstance(item, str):
            return game_items_single(self.session, self.grant, item)

        return game_items_batch(self.session, self.grant, item)

    @require_auth
    def get_game_offers_list(self):
        return game_offers_list(self.session, self.grant)

    @require_auth
    def get_game_offers(self, offer):
        if isinstance(offer, str):
            return game_offers_single(self.session, self.grant, offer)

        return game_offers_batch(self.session, self.grant, offer)

    @require_auth
    def redeem_game_offer(self, offer, currency, transaction, parent=None):
        return game_offers_redeem(self.session, self.grant, self.guid, offer, currency, transaction, parent=parent)

    @require_auth
    def rent_game_offer(self, offer, currency, transaction, parent=None):
        return game_offers_rent(self.session, self.grant, self.guid, offer, currency, transaction, parent=parent)

    @require_auth
    def get_advertisement(self, advertisement):
        return matchmaking_advertisement(self.session, self.grant, advertisement)

    @require_auth
    def create_matchmaking_advertisement(self, gameversion, region, users, gametype=None, party=None):
        advertisement = generate_advertisement_matchmaking(gameversion, region, self.guid, users, gametype, party)

        return matchmaking_advertisement_create(self.session, self.grant, advertisement)

    @require_auth
    def create_server_advertisement(self, gameversion, region, server, users, party=None):
        advertisement = generate_advertisement_server(gameversion, region, server, self.guid, users, party)

        return matchmaking_advertisement_create(self.session, self.grant, advertisement)

    @require_auth
    def delete_advertisement(self, advertisement):
        return matchmaking_advertisement_delete(self.session, self.grant, advertisement)

    @require_auth
    def get_presence_access(self):
        return presence_access(self.session, self.grant, self.guid)

    @require_auth
    def get_presence_domain(self):
        return presence_domain(self.session, self.grant, self.guid)

    @require_auth
    def get_server_list(self):
        return server_list(self.session, self.grant)

    @require_auth
    def get_server(self, server):
        return server_single(self.session, self.grant, server)

    @require_auth
    def get_server_by_name(self, name):
        servers = []
        name = name.lower()
        for server in server_list(self.session, self.grant):
            if server["ServerName"].lower() == name:
                servers.append(server)

        return servers

    @require_auth
    def get_stat_overflow_list(self):
        return stat_overflow_list(self.session, self.grant)

    @require_auth
    def get_stat_overflow(self, overflow):
        return stat_overflow_single(self.session, self.grant, overflow)

    @require_auth
    def transfer_stat_overflow_from_item(self, item, overflow, amount):
        return stat_overflow_transfer_from(self.session, self.grant, self.guid, item, overflow, amount)

    @require_auth
    def transfer_stat_overflow_to_item(self, item, overflow, amount):
        return stat_overflow_transfer_to(self.session, self.grant, self.guid, item, overflow, amount)

    def get_game_status(self):
        return status_game(self.session)

    def get_services_status(self):
        return status_services(self.session)

    @require_auth
    def get_user(self, identifier):
        return user_account(self.session, self.grant, identifier)

    @require_auth
    def get_user_clan(self, user):
        return user_clan(self.session, self.grant, user)

    @require_auth
    def get_eula_status(self, user):
        return user_eula_read(self.session, self.grant, user)

    @require_auth
    def get_user_game_settings(self, user):
        return user_game_settings(self.session, self.grant, user)

    @require_auth
    def create_user_game_settings(self, settings):
        return user_game_settings_create(self.session, self.grant, self.guid, settings)

    @require_auth
    def update_user_game_settings(self, settings):
        return user_game_settings_update(self.session, self.grant, self.guid, settings)

    @require_auth
    def delete_user_game_settings(self):
        return user_game_settings_delete(self.session, self.grant, self.guid)

    def get_user_guid(self, callsign):
        return user_guid(self.session, callsign)

    @require_auth
    def get_user_items_list(self, user):
        return user_items(self.session, self.grant, user)

    @require_auth
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

    @require_auth
    def update_user_item(self, item, data):
        return user_items_broker(self.session, self.grant, self.guid, item, data)

    @require_auth
    def get_user_items_stats_list(self, user):
        return user_items_stats(self.session, self.grant, user)

    @require_auth
    def get_user_item_stats(self, user, item):
        return user_items_stats_single(self.session, self.grant, user, item)

    @require_auth
    def get_meteor_settings(self, user):
        return user_meteor_settings(self.session, self.grant, user)

    @require_auth
    def get_user_legacy_data(self, user):
        return user_publicdata_single(self.session, self.grant, user)

    @require_auth
    def get_user_callsign(self, user):
        response = user_publicdata_single(self.session, self.grant, user)

        if response is not None:
            # Some users don't have a callsign
            return response.get("UniqueCaseInsensitive_Callsign", None)

        return None

    @require_auth
    def get_user_server(self, user):
        return user_server(self.session, self.grant, user)

    @require_auth
    def get_user_stats(self, user):
        if isinstance(user, str):
            return user_stats_single(self.session, self.grant, user)

        return user_stats_batch(self.session, self.grant, user)

    @require_auth
    def create_transaction(self):
        return user_transaction(self.session, self.grant, self.guid)

    def get_version(self):
        return version(self.session)

    @require_auth
    def get_voice_access(self):
        return voice_access(self.session, self.grant, self.guid)

    @require_auth
    def get_voice_info(self):
        return voice_info(self.session, self.grant)

    @require_auth
    def get_voice_user_info(self, voice):
        return voice_lookup(self.session, self.grant, voice)

    @require_auth
    def get_voice_user_id(self, user):
        return voice_user(self.session, self.grant, user)

    @require_auth
    def get_voice_channel(self, channel):
        return voice_channel(self.session, self.grant, channel)
