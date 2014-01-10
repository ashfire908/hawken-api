# -*- coding: utf-8 -*-

from sleekxmpp.xmlstream.stanzabase import ElementBase
from hawkenapi.util import enum

MemberDataCodes = enum(InvitePlayer="InvitePlayerToParty", MatchmakingStart="PartyMatchmakingStart", MatchmakingCancel="PartyMatchmakingCancel", DeployParty="DeployPartyData", DeployCancel="DeployCancelData")


class GameInvite(ElementBase):
    name = "invite"
    namespace = "urn:meteor:invite"
    plugin_attrib = "invite"
    interfaces = {"invite", }
    is_extension = True

    def get_invite(self):
        return self.xml.text

    def set_invite(self, value):
        self.xml.text = value


class StormId(ElementBase):
    name = "stormid"
    namespace = "urn:meteor:stormidext"
    plugin_attrib = "stormid"
    interfaces = {"stormid", }
    is_extension = True

    def get_stormid(self):
        return self.xml.text

    def set_stormid(self, value):
        self.xml.text = value


class PartyMemberData(ElementBase):
    name = "partymemberdata"
    namespace = "urn:meteor:partymemberdata"
    plugin_attrib = "partymemberdata"
    interfaces = {"playerId", "infoName", "infoValue"}


class PartyVoiceChannel(ElementBase):
    name = "voicechanneldata"
    namespace = "urn:meteor:partyvoicechannel"
    plugin_attrib = "partyvoicechannel"
    interfaces = {"voiceurl", }
