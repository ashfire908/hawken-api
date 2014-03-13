# -*- coding: utf-8 -*-

from enum import Enum
from sleekxmpp.xmlstream.stanzabase import ElementBase


class MemberDataCodes(str, Enum):
    invite_player = "InvitePlayerToParty"
    matchmaking_start = "PartyMatchmakingStart"
    matchmaking_cancel = "PartyMatchmakingCancel"
    deploy_party = "DeployPartyData"
    deploy_cancel = "DeployCancelData"


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
