# -*- coding: utf-8 -*-
# High-level API Client

import time
from datetime import datetime
import logging
from hawkenapi.interface import *
from hawkenapi.exceptions import NotAuthenticated, NotAuthorized, InternalServerError, ServiceUnavailable, \
    RequestError, RetryLimitExceeded, InvalidBatch
from hawkenapi.util import JWTParser, chunks

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
    def __init__(self, retry_attempts=1, retry_delay=1, **kwargs):
        self._interface = Interface(**kwargs)

        # Init auth data
        self._grant = None
        self.identifier = None
        self.password = None

        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

        self._batch_limit = 200

    def _request(self, endpoint, *args, **kwargs):
        last_exception = None
        i = 0
        success = False
        response = None
        while self.retry_attempts > i:
            try:
                response = endpoint(self._interface, *args, **kwargs)
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
        grant = self._request(auth, identifier, password)

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
            result = self._request(deauth, str(self.grant), self.guid)
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
        return self._request(achievement_list, self.grant, countrycode=countrycode)

    @require_auth
    def get_achievements(self, achievement, countrycode=None):
        if isinstance(achievement, str):
            # Emulate a single-type request
            try:
                data = self._request(achievement_batch, self.grant, [achievement], countrycode=countrycode)
            except InvalidBatch:
                return None

            return data[0]

        # Perform a chunked batch request
        data = []
        for chunk in chunks(achievement, self._batch_limit):
            data.extend(self._request(achievement_batch, self.grant, chunk, countrycode=countrycode))

        return data

    @require_auth
    def get_achievement_rewards_list(self, countrycode=None):
        return self._request(achievement_reward_list, self.grant, countrycode=countrycode)

    @require_auth
    def get_achievement_rewards(self, achievement, countrycode=None):
        if isinstance(achievement, str):
            return self._request(achievement_reward_single, self.grant, achievement, countrycode=countrycode)

        # Perform a chunked batch request
        data = []
        for chunk in chunks(achievement, self._batch_limit):
            data.extend(self._request(achievement_reward_batch, self.grant, chunk, countrycode=countrycode))

        return data

    @require_auth
    def get_user_achievements_list(self, user):
        return self._request(achievement_user_list, self.grant, user)

    @require_auth
    def get_user_achievements(self, user, achievement):
        if isinstance(achievement, str):
            # Emulate a single-type request
            try:
                data = self._request(achievement_user_batch, self.grant, user, [achievement])
            except InvalidBatch:
                return None

            if data:
                return data[0]

            return data

        # Perform a chunked batch request
        data = []
        for chunk in chunks(achievement, self._batch_limit):
            response = self._request(achievement_user_batch, self.grant, user, chunk)
            if response is None:
                # No such user
                return None

            data.extend(response)

        return data

    @require_auth
    def unlock_achievement(self, achievement):
        return self._request(achievement_user_unlock, self.grant, self.guid, achievement)

    @require_auth
    def get_antiaddition(self, user):
        return self._request(antiaddiction, self.grant, user)

    @require_auth
    def get_clan_list(self, tag=None, name=None):
        return self._request(clan_list, self.grant, tag=tag, name=name)

    @require_auth
    def get_clan(self, clan):
        return self._request(clan_single, self.grant, clan)

    @require_auth
    def get_clan_users(self, clan):
        return self._request(clan_users, self.grant, clan)

    @require_auth
    def get_hawken_credits(self, user):
        return self._request(currency_hawken, self.grant, user)

    @require_auth
    def get_meteor_credits(self, user):
        return self._request(currency_meteor, self.grant, user)

    def get_events_url(self):
        return self._request(events_url)

    @require_auth
    def get_game_items(self, item=None):
        if item is None:
            return self._request(game_items, self.grant)
        elif isinstance(item, str):
            return self._request(game_items_single, self.grant, item)

        return self._request(game_items_batch, self.grant, item)

    @require_auth
    def get_game_offers_list(self):
        return self._request(game_offers_list, self.grant)

    @require_auth
    def get_game_offers(self, offer):
        if isinstance(offer, str):
            return self._request(game_offers_single, self.grant, offer)

        return self._request(game_offers_batch, self.grant, offer)

    @require_auth
    def redeem_game_offer(self, offer, currency, transaction, parent=None):
        return self._request(game_offers_redeem, self.grant, self.guid, offer, currency, transaction, parent=parent)

    @require_auth
    def rent_game_offer(self, offer, currency, transaction, parent=None):
        return self._request(game_offers_rent, self.grant, self.guid, offer, currency, transaction, parent=parent)

    @require_auth
    def get_advertisement(self, advertisement):
        return self._request(matchmaking_advertisement, self.grant, advertisement)

    @require_auth
    def create_matchmaking_advertisement(self, gameversion, region, users, gametype=None, party=None):
        advertisement = generate_advertisement_matchmaking(gameversion, region, self.guid, users, gametype, party)

        return self._request(matchmaking_advertisement_create, self.grant, advertisement)

    @require_auth
    def create_server_advertisement(self, gameversion, region, server, users, party=None):
        advertisement = generate_advertisement_server(gameversion, region, server, self.guid, users, party)

        return self._request(matchmaking_advertisement_create, self.grant, advertisement)

    @require_auth
    def delete_advertisement(self, advertisement):
        return self._request(matchmaking_advertisement_delete, self.grant, advertisement)

    @require_auth
    def get_presence_access(self):
        return self._request(presence_access, self.grant, self.guid)

    @require_auth
    def get_presence_domain(self):
        return self._request(presence_domain, self.grant, self.guid)

    @require_auth
    def get_server(self, server=None):
        if server is None:
            return self._request(server_list, self.grant)

        return self._request(server_single, self.grant, server)

    @require_auth
    def get_server_by_name(self, name):
        servers = []
        name = name.lower()
        for server in self._request(server_list, self.grant):
            if server["ServerName"].lower() == name:
                servers.append(server)

        return servers

    @require_auth
    def get_stat_overflow_list(self):
        return self._request(stat_overflow_list, self.grant)

    @require_auth
    def get_stat_overflow(self, overflow):
        return self._request(stat_overflow_single, self.grant, overflow)

    @require_auth
    def transfer_stat_overflow_from_item(self, item, overflow, amount):
        return self._request(stat_overflow_transfer_from, self.grant, self.guid, item, overflow, amount)

    @require_auth
    def transfer_stat_overflow_to_item(self, item, overflow, amount):
        return self._request(stat_overflow_transfer_to, self.grant, self.guid, item, overflow, amount)

    def get_game_status(self):
        return self._request(status_game)

    def get_services_status(self):
        return self._request(status_services)

    @require_auth
    def get_user(self, identifier):
        return self._request(user_account, self.grant, identifier)

    @require_auth
    def get_user_clan(self, user):
        return self._request(user_clan, self.grant, user)

    @require_auth
    def get_eula_status(self):
        return self._request(user_eula_read, self.grant, self.guid)

    @require_auth
    def get_user_game_settings(self, user):
        return self._request(user_game_settings, self.grant, user)

    @require_auth
    def create_user_game_settings(self, settings):
        return self._request(user_game_settings_create, self.grant, self.guid, settings)

    @require_auth
    def update_user_game_settings(self, settings):
        return self._request(user_game_settings_update, self.grant, self.guid, settings)

    @require_auth
    def delete_user_game_settings(self):
        return self._request(user_game_settings_delete, self.grant, self.guid)

    def get_user_guid(self, callsign):
        return self._request(user_guid, callsign)

    @require_auth
    def get_user_items(self, user, item=None):
        if item is None:
            return self._request(user_items, self.grant, user)
        elif isinstance(item, str):
            # Emulate a single-type request
            try:
                data = self._request(user_items_batch, self.grant, user, [item])
            except InvalidBatch:
                return None

            if data:
                return data[0]

            return data

        return self._request(user_items_batch, self.grant, user, item)

    @require_auth
    def update_user_item(self, item, data):
        return self._request(user_items_broker, self.grant, self.guid, item, data)

    @require_auth
    def get_user_item_stats(self, user, item=None):
        if item is None:
            return self._request(user_items_stats, self.grant, user)

        return self._request(user_items_stats_single, self.grant, user, item)

    @require_auth
    def get_meteor_settings(self):
        return self._request(user_meteor_settings, self.grant, self.guid)

    @require_auth
    def get_user_legacy_data(self, user):
        return self._request(user_publicdata_single, self.grant, user)

    @require_auth
    def get_user_callsign(self, user):
        response = self._request(user_publicdata_single, self.grant, user)

        if response is not None:
            # Some users don't have a callsign
            return response.get("UniqueCaseInsensitive_Callsign", None)

        return None

    @require_auth
    def get_user_server(self, user):
        return self._request(user_server, self.grant, user)

    @require_auth
    def get_user_stats(self, user):
        if isinstance(user, str):
            return self._request(user_stats_single, self.grant, user)

        # Perform a chunked batch request
        data = []
        for chunk in chunks(user, self._batch_limit):
            data.extend(self._request(user_stats_batch, self.grant, user))

        return data

    @require_auth
    def create_transaction(self):
        return self._request(user_transaction, self.grant, self.guid)

    def get_version(self):
        return self._request(version)

    @require_auth
    def get_voice_access(self):
        return self._request(voice_access, self.grant, self.guid)

    @require_auth
    def get_voice_info(self):
        return self._request(voice_info, self.grant)

    @require_auth
    def get_voice_user_info(self, voice):
        return self._request(voice_lookup, self.grant, voice)

    @require_auth
    def get_voice_user_id(self, user):
        return self._request(voice_user, self.grant, user)

    @require_auth
    def get_voice_channel(self, channel):
        return self._request(voice_channel, self.grant, channel)
