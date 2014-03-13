# -*- coding: utf-8 -*-

from enum import Enum
import urllib.parse
from hawkenapi.util import create_flags


# Methods and flags
class Methods(str, Enum):
    get = "GET"
    post = "POST"
    put = "PUT"
    delete = "DELETE"

Flags = create_flags("authrequired", "batchheader", "batchpost")


# Endpoint class
class Endpoint:
    def __init__(self, endpoint, fields=(), methods=(), flags=()):
        self._endpoint = endpoint
        self.fields = fields
        self.methods = methods
        self.flags = Flags(*flags)

    def __str__(self):
        return self._endpoint

    def format_url(self, *arguments):
        # Quote the arguments
        arguments = [urllib.parse.quote(argument) for argument in arguments]

        # Generate the endpoint
        endpoint = self._endpoint.format(*arguments)

        # Return the endpoint
        return endpoint

    def format_fields(self, **fields):
        # Verify the query fields
        query = {}
        if len(fields) > 0:
            field_search = [field.lower() for field in self.fields]
            for field, value in fields.items():
                if field.lower in field_search and value is not None:
                    query[field] = value

        return query


# Define the API endpoints
achievement = Endpoint("achievements", fields=("countryCode", ), methods=(Methods.get, ), flags=("authrequired", ))
achievement_batch = Endpoint("achievementsBatch", fields=("countryCode", ), methods=(Methods.get, ), flags=("authrequired", "batchheader"))
achievement_reward = Endpoint("achievementReward", fields=("countryCode", ), methods=(Methods.get, ), flags=("authrequired", ))
achievement_reward_batch = Endpoint("achievementRewardBatch", fields=("countryCode", ), methods=(Methods.get, ), flags=("authrequired", "batchheader"))
achievement_reward_single = Endpoint("achievementReward/{0}", fields=("countryCode", ), methods=(Methods.get, ), flags=("authrequired", ))
achievement_user = Endpoint("userAchievements/{0}", methods=(Methods.get, ), flags=("authrequired", "batchheader"))
achievement_user_client = Endpoint("userClientAchievements/{0}/{1}", methods=(Methods.post, ), flags=("authrequired", ))
advertisement = Endpoint("hawkenClientMatchmakingAdvertisements", methods=(Methods.post, ), flags=("authrequired", ))
advertisement_single = Endpoint("hawkenClientMatchmakingAdvertisements/{0}", methods=(Methods.get, Methods.delete), flags=("authrequired", ))
antiaddiction = Endpoint("antiAddictionModNumber/{0}", methods=(Methods.get, ), flags=("authrequired", ))
bundle = Endpoint("bundles", methods=(Methods.get, ), flags=("authrequired", "batchheader"))
bundle_redeem = Endpoint("redeemBundles/{0}", methods=(Methods.post, ), flags=("authrequired", ))
bundle_single = Endpoint("bundles/{0}", methods=(Methods.get, ), flags=("authrequired", ))
clan = Endpoint("clans", fields=("clanTag", "clanName"), methods=(Methods.get, Methods.post), flags=("authrequired", ))
clan_single = Endpoint("clans/{0}", methods=(Methods.get, Methods.post, Methods.put, Methods.delete), flags=("authrequired", ))
clan_users = Endpoint("clans/{0}/users", methods=(Methods.get, Methods.post), flags=("authrequired", ))
currency_game = Endpoint("gameCurrency/{0}", methods=(Methods.get, ), flags=("authrequired", ))
currency_meteor = Endpoint("meteorCurrency/{0}", methods=(Methods.get, ), flags=("authrequired", ))
eventsurl = Endpoint("eventsurl", methods=(Methods.get, ))
item = Endpoint("gameItems", methods=(Methods.get, ), flags=("authrequired", ))
item_batch = Endpoint("gameItemsBatch", methods=(Methods.post, ), flags=("authrequired", "batchpost"))
item_single = Endpoint("gameItems/{0}", methods=(Methods.get, ), flags=("authrequired", ))
offer = Endpoint("gameOffers", methods=(Methods.get, ), flags=("authrequired", ))
offer_batch = Endpoint("gameOffersBatch", methods=(Methods.post, ), flags=("authrequired", "batchpost"))
offer_single = Endpoint("gameOffers/{0}", methods=(Methods.get, ), flags=("authrequired", ))
offer_redeemer = Endpoint("userGameOfferRedeemer/{0}/{1}", methods=(Methods.post, ), flags=("authrequired", ))
offer_renter = Endpoint("userGameOfferRenter/{0}/{1}", methods=(Methods.post, ), flags=("authrequired", ))
server = Endpoint("gameServerListings", methods=(Methods.get, ), flags=("authrequired", ))
server_single = Endpoint("gameServerListings/{0}", methods=(Methods.get, ), flags=("authrequired", ))
server_user = Endpoint("userGameServers/{0}", methods=(Methods.get, ), flags=("authrequired", ))
presence_access = Endpoint("thirdParty/{0}/Presence/Access", methods=(Methods.get, ), flags=("authrequired", ))
presence_domain = Endpoint("thirdParty/{0}/Presence/Domain", methods=(Methods.get, ), flags=("authrequired", ))
statoverflow = Endpoint("statOverflow", methods=(Methods.get, ), flags=("authrequired", ))
statoverflow_single = Endpoint("statOverflow/{0}", methods=(Methods.get, ), flags=("authrequired", ))
statoverflow_transfer = Endpoint("users/{0}/statTransfer/{1}", methods=(Methods.post, Methods.put), flags=("authrequired", ))
status_gameclient = Endpoint("status/game_client", methods=(Methods.get, ))
status_services = Endpoint("status/services", methods=(Methods.get, ))
transaction = Endpoint("userGameTransaction/{0}", methods=(Methods.post, ), flags=("authrequired", ))
uniquevalues = Endpoint("uniqueValues", methods=(Methods.get, ))
uniquevalues_callsign = Endpoint("uniqueValues/UniqueCaseInsensitive_UserPublicReadOnlyData_Callsign/{0}", methods=(Methods.get, ))
user = Endpoint("users/{0}", methods=(Methods.get, ), flags=("authrequired", ))
user_accessgrant = Endpoint("users/{0}/accessGrant", methods=(Methods.post, Methods.put))
user_clan = Endpoint("users/{0}/clans", methods=(Methods.get, ), flags=("authrequired", ))
user_eula = Endpoint("userReadEula/{0}", methods=(Methods.get, ), flags=("authrequired", ))
user_item = Endpoint("userGameItems/{0}", methods=(Methods.get, ), flags=("authrequired", ))
user_item_batch = Endpoint("userGameItemsBatch/{0}", methods=(Methods.post, ), flags=("authrequired", "batchpost"))
user_item_broker = Endpoint("userGameItemsBroker/{0}/{1}", methods=(Methods.put, ), flags=("authrequired", ))
user_item_stat = Endpoint("userGameItemStats/{0}", methods=(Methods.get, ), flags=("authrequired", ))
user_item_stat_single = Endpoint("userGameItemStats/{0}/{1}", methods=(Methods.get, ), flags=("authrequired", ))
user_meteor_batch = Endpoint("userMeteorSettings", methods=(Methods.get, ), flags=("authrequired", "batchheader"))
user_meteor_single = Endpoint("userMeteorSettings/{0}", methods=(Methods.get, ), flags=("authrequired", ))
user_publicdata_batch = Endpoint("userPublicReadOnlyData", methods=(Methods.get, ), flags=("authrequired", "batchheader"))
user_publicdata_single = Endpoint("userPublicReadOnlyData/{0}", methods=(Methods.get, ), flags=("authrequired", ))
user_settings_batch = Endpoint("userGameSettings", methods=(Methods.get, ), flags=("authrequired", "batchheader"))
user_settings_single = Endpoint("userGameSettings/{0}", methods=(Methods.get, Methods.post, Methods.put, Methods.delete), flags=("authrequired", ))
user_stat_batch = Endpoint("userStats", methods=(Methods.get, ), flags=("authrequired", "batchheader"))
user_stat_single = Endpoint("userStats/{0}", methods=(Methods.get, ), flags=("authrequired", ))
version = Endpoint("version", methods=(Methods.get, ))
voice_access = Endpoint("thirdParty/{0}/Vivox/Access", methods=(Methods.get, ), flags=("authrequired", ))
voice_info = Endpoint("voiceInfo", methods=(Methods.get, ), flags=("authrequired", ))
voice_lookup = Endpoint("vivoxLookup/{0}", methods=(Methods.get, ), flags=("authrequired", ))
voice_user = Endpoint("thirdParty/{0}/Vivox/User", methods=(Methods.get, ), flags=("authrequired", ))
voice_channel = Endpoint("voiceChannelListings/{0}", methods=(Methods.get, ), flags=("authrequired", ))
