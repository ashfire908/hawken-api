# -*- coding: utf-8 -*-

import urllib.parse
from hawkenapi.util import enum, create_bitfield


# Enums
Methods = enum(GET="GET", POST="POST", PUT="PUT", DELETE="DELETE")
Flags = create_bitfield("authrequired", "batchheader", "batchpost")


# Endpoint class
class Endpoint:
    def __init__(self, endpoint, fields=(), methods=(), flags=()):
        self._endpoint = endpoint
        self.fields = fields
        self.methods = methods
        self.flags = Flags(flags)

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
        if len(fields) > 0:
            field_search = [field.lower() for field in self.fields]
            for field, value in fields.items():
                if field.lower in field_search and value is not None:
                    query[field] = value

        # Append the query string
        if len(query) > 0:
            endpoint = "{}?{}".format(endpoint, urllib.parse.urlencode(query))

        # Return the endpoint
        return endpoint


# Define the API endpoints
achievement = Endpoint("achievements", fields=("countryCode", ), methods=(Methods.GET, ), flags=("authrequired", ))
achievement_batch = Endpoint("achievementsBatch", fields=("countryCode", ), methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
achievement_reward = Endpoint("achievementReward", fields=("countryCode", ), methods=(Methods.GET, ), flags=("authrequired", ))
achievement_reward_batch = Endpoint("achievementRewardBatch", fields=("countryCode", ), methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
achievement_reward_single = Endpoint("achievementReward/{0}", fields=("countryCode", ), methods=(Methods.GET, ), flags=("authrequired", ))
achievement_user = Endpoint("userAchievements/{0}", methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
achievement_user_client = Endpoint("userClientAchievements/{0}/{1}", methods=(Methods.POST, ), flags=("authrequired", ))
advertisement = Endpoint("hawkenClientMatchmakingAdvertisements", methods=(Methods.POST, ), flags=("authrequired", ))
advertisement_single = Endpoint("hawkenClientMatchmakingAdvertisements/{0}", methods=(Methods.GET, Methods.DELETE), flags=("authrequired", ))
antiaddiction = Endpoint("antiAddictionModNumber/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
bundle = Endpoint("bundles", methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
bundle_redeem = Endpoint("redeemBundles/{0}", methods=(Methods.POST, ), flags=("authrequired", ))
bundle_single = Endpoint("bundles/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
clan = Endpoint("clans", fields=("clanTag", "clanName"), methods=(Methods.GET, Methods.POST), flags=("authrequired", ))
clan_single = Endpoint("clans/{0}", methods=(Methods.GET, Methods.POST, Methods.PUT, Methods.DELETE), flags=("authrequired", ))
clan_users = Endpoint("clans/{0}/users", methods=(Methods.GET, Methods.POST), flags=("authrequired", ))
currency_game = Endpoint("gameCurrency/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
currency_meteor = Endpoint("meteorCurrency/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
eventsurl = Endpoint("eventsurl", methods=(Methods.GET, ))
item = Endpoint("gameItems", methods=(Methods.GET, ), flags=("authrequired", ))
item_batch = Endpoint("gameItemsBatch", methods=(Methods.POST, ), flags=("authrequired", "batchpost"))
item_single = Endpoint("gameItems/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
offer = Endpoint("gameOffers", methods=(Methods.GET, ), flags=("authrequired", ))
offer_batch = Endpoint("gameOffersBatch", methods=(Methods.POST, ), flags=("authrequired", "batchpost"))
offer_single = Endpoint("gameOffers/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
offer_redeemer = Endpoint("userGameOfferRedeemer/{0}/{1}", methods=(Methods.POST, ), flags=("authrequired", ))
offer_renter = Endpoint("userGameOfferRenter/{0}/{1}", methods=(Methods.POST, ), flags=("authrequired", ))
server = Endpoint("gameServerListings", methods=(Methods.GET, ), flags=("authrequired", ))
server_single = Endpoint("gameServerListings/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
server_user = Endpoint("userGameServers/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
presence_access = Endpoint("thirdParty/{0}/Presence/Access", methods=(Methods.GET, ), flags=("authrequired", ))
presence_domain = Endpoint("thirdParty/{0}/Presence/Domain", methods=(Methods.GET, ), flags=("authrequired", ))
statoverflow = Endpoint("statOverflow", methods=(Methods.GET, ), flags=("authrequired", ))
statoverflow_single = Endpoint("statOverflow/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
statoverflow_transfer = Endpoint("users/{0}/statTransfer/{1}", methods=(Methods.POST, Methods.PUT), flags=("authrequired", ))
status_gameclient = Endpoint("status/game_client", methods=(Methods.GET, ))
status_services = Endpoint("status/services", methods=(Methods.GET, ))
transaction = Endpoint("userGameTransaction/{0}", methods=(Methods.POST, ), flags=("authrequired", ))
uniquevalues = Endpoint("uniqueValues", methods=(Methods.GET, ))
uniquevalues_callsign = Endpoint("uniqueValues/UniqueCaseInsensitive_UserPublicReadOnlyData_Callsign/{0}", methods=(Methods.GET, ))
user = Endpoint("users/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
user_accessgrant = Endpoint("users/{0}/accessGrant", methods=(Methods.POST, Methods.PUT))
user_clan = Endpoint("users/{0}/clans", methods=(Methods.GET, ), flags=("authrequired", ))
user_eula = Endpoint("userReadEula/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
user_item = Endpoint("userGameItems/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
user_item_batch = Endpoint("userGameItemsBatch/{0}", methods=(Methods.POST, ), flags=("authrequired", "batchpost"))
user_item_broker = Endpoint("userGameItemsBroker/{0}/{1}", methods=(Methods.PUT, ), flags=("authrequired", ))
user_item_stat = Endpoint("userGameItemStats/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
user_item_stat_single = Endpoint("userGameItemStats/{0}/{1}", methods=(Methods.GET, ), flags=("authrequired", ))
user_meteor_batch = Endpoint("userMeteorSettings", methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
user_meteor_single = Endpoint("userMeteorSettings/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
user_publicdata_batch = Endpoint("userPublicReadOnlyData", methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
user_publicdata_single = Endpoint("userPublicReadOnlyData/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
user_settings_batch = Endpoint("userGameSettings", methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
user_settings_single = Endpoint("userGameSettings/{0}", methods=(Methods.GET, Methods.POST, Methods.PUT, Methods.DELETE), flags=("authrequired", ))
user_stat_batch = Endpoint("userStats", methods=(Methods.GET, ), flags=("authrequired", "batchheader"))
user_stat_single = Endpoint("userStats/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
version = Endpoint("version", methods=(Methods.GET, ))
voice_access = Endpoint("thirdParty/{0}/Vivox/Access", methods=(Methods.GET, ), flags=("authrequired", ))
voice_info = Endpoint("voiceInfo", methods=(Methods.GET, ), flags=("authrequired", ))
voice_lookup = Endpoint("vivoxLookup/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
voice_user = Endpoint("thirdParty/{0}/Vivox/User", methods=(Methods.GET, ), flags=("authrequired", ))
voice_channel = Endpoint("voiceChannelListings/{0}", methods=(Methods.GET, ), flags=("authrequired", ))
