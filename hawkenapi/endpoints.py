# -*- coding: utf-8 -*-

import urllib.parse
from hawkenapi.util import enum


# Enums
Methods = enum(GET="GET", POST="POST", PUT="PUT", DELETE="DELETE")


# Base endpoint class
class Endpoint:
    def __init__(self, endpoint, fields=(), methods=()):
        self._endpoint = endpoint
        self.fields = fields
        self.methods = methods

    def __str__(self):
        return self._endpoint

    def format(self, *arguments, **fields):
        # Quote the arguments
        for argument in arguments:
            argument = urllib.parse.quote(argument)

        # Generate the endpoint
        endpoint = self._endpoint.format(*arguments)

        # Verify the query fields
        query = {}
        for field, value in fields.items():
            if field in self.fields:
                query[field] = value

        # Append the query string
        if len(query) > 0:
            endpoint = "{}?{}".format(endpoint, urllib.parse.urlencode(query))

        # Return the endpoint
        return endpoint

# Define the API endpoints
achievement = Endpoint("achievements", fields=("countryCode"), methods=(Methods.GET))
achievement_batch = Endpoint("achievementsBatch", fields=("countryCode"), methods=(Methods.GET))
achievement_reward = Endpoint("achievementReward", fields=("countryCode"), methods=(Methods.GET))
achievement_reward_batch = Endpoint("achievementRewardBatch", fields=("countryCode"), methods=(Methods.GET))
achievement_reward_single = Endpoint("achievementReward/{0}", fields=("countryCode"), methods=(Methods.GET))
achievement_user = Endpoint("userAchievements/{0}", methods=(Methods.GET))
achievement_user_client = Endpoint("userClientAchievements/{0}/{1}", methods=(Methods.POST))
advertisement = Endpoint("hawkenClientMatchmakingAdvertisements", methods=(Methods.POST))
advertisement_single = Endpoint("hawkenClientMatchmakingAdvertisements/{0}", methods=(Methods.GET, Methods.DELETE))
antiaddiction = Endpoint("antiAddictionModNumber/{0}", methods=(Methods.GET))
bundle = Endpoint("bundles", methods=(Methods.GET))
bundle_redeem = Endpoint("redeemBundles/{0}", methods=(Methods.POST))
bundle_single = Endpoint("bundles/{0}", methods=(Methods.GET))
clan = Endpoint("clans", fields=("clanTag", "clanName"), methods=(Methods.GET, Methods.POST))
clan_single = Endpoint("clans/{0}", methods=(Methods.GET, Methods.POST, Methods.PUT, Methods.DELETE))
clan_users = Endpoint("clans/{0}/users", methods=(Methods.GET, Methods.POST))
currency_game = Endpoint("gameCurrency/{0}", methods=(Methods.GET))
currency_meteor = Endpoint("meteorCurrency/{0}", methods=(Methods.GET))
eventsurl = Endpoint("eventsurl", methods=(Methods.GET))
item = Endpoint("gameItems", methods=(Methods.GET))
item_batch = Endpoint("gameItemsBatch", methods=(Methods.GET))
item_single = Endpoint("gameItems/{0}", methods=(Methods.GET))
item_user = Endpoint("userGameItems/{0}", methods=(Methods.GET))
item_user_batch = Endpoint("userGameItemsBatch/{0}", methods=(Methods.POST))
item_user_broker = Endpoint("userGameItemsBroker/{0}/{1}", methods=(Methods.PUT))
item_user_redeemer = Endpoint("userGameOfferRedeemer/{0}/{1}", methods=(Methods.POST))
item_user_renter = Endpoint("userGameOfferRenter/{0}/{1}", methods=(Methods.POST))
item_user_stat = Endpoint("userGameItemStats/{0}", methods=(Methods.GET))
item_user_stat_single = Endpoint("userGameItemStats/{0}/{1}", methods=(Methods.GET))
offer = Endpoint("gameOffers", methods=(Methods.GET))
offer_batch = Endpoint("gameOffersBatch", methods=(Methods.POST))
offer_single = Endpoint("gameOffers/{0}", methods=(Methods.GET))
server = Endpoint("gameServerListings", methods=(Methods.GET))
server_single = Endpoint("gameServerListings/{0}", methods=(Methods.GET))
server_user = Endpoint("userGameServers/{0}", methods=(Methods.GET))
presence_access = Endpoint("thirdParty/{0}/Presence/Access", methods=(Methods.GET))
presence_domain = Endpoint("thirdParty/{0}/Presence/Domain", methods=(Methods.GET))
statoverflow = Endpoint("statOverflow", methods=(Methods.GET))
statoverflow_single = Endpoint("statOverflow/{0}", methods=(Methods.GET))
statoverflow_transfer = Endpoint("users/{0}/statTransfer/{1}", methods=(Methods.POST, Methods.PUT))
status_single = Endpoint("status/{0}", methods=(Methods.GET))
transaction = Endpoint("userGameTransaction", methods=(Methods.POST))
uniquevalues = Endpoint("uniqueValues", methods=(Methods.GET))
uniquevalues_callsign = Endpoint("uniqueValues/UniqueCaseInsensitive_UserPublicReadOnlyData_Callsign/{0}", methods=(Methods.GET))
user = Endpoint("users/{0}", methods=(Methods.GET))
user_accessgrant = Endpoint("users/{0}/accessGrant", methods=(Methods.POST, Methods.PUT))
user_clan = Endpoint("users/{0}/clans", methods=(Methods.GET))
user_eula = Endpoint("userReadEula/{0}", methods=(Methods.GET))
user_publicdata_batch = Endpoint("userPublicReadOnlyData", methods=(Methods.GET))
user_publicdata_single = Endpoint("userPublicReadOnlyData/{0}", methods=(Methods.GET))
user_settings_batch = Endpoint("userGameSettings", methods=(Methods.GET))
user_settings_single = Endpoint("userGameSettings/{0}", methods=(Methods.GET, Methods.POST, Methods.PUT, Methods.DELETE))
user_stat_batch = Endpoint("userStats", methods=(Methods.GET))
user_stat_single = Endpoint("userStats/{0}", methods=(Methods.GET))
version = Endpoint("version", methods=(Methods.GET))
vivox_access = Endpoint("thirdParty/{0}/Vivox/Access", methods=(Methods.GET))
vivox_info = Endpoint("voiceInfo", methods=(Methods.GET))
vivox_lookup = Endpoint("vivoxLookup/{0}", methods=(Methods.GET))
vivox_user = Endpoint("thirdParty/{0}/Vivox/User", methods=(Methods.GET))
voice_channel = Endpoint("voiceChannelListings/{0}", methods=(Methods.GET))
