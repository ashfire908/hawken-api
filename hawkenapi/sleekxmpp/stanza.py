# -*- coding: utf-8 -*-

from sleekxmpp.xmlstream.stanzabase import ElementBase


class StormId(ElementBase):
    name = "stormid"
    namespace = "urn:meteor:stormidext"
    plugin_attrib = "stormid"
    interfaces = set(())

    def __getattr__(self, name):
        if name == "id":
            return self.xml.text
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if name == "id":
            self.xml.text = value
        else:
            super(StormId, self).__setattr__(name, value)


class PartyMemberData(ElementBase):
    name = "partymemberdata"
    namespace = "urn:meteor:partymemberdata"
    plugin_attrib = "partymemberdata"
    interfaces = set(("playerId", "infoName", "infoValue"))


class PartyVoiceChannel(ElementBase):
    name = "voicechanneldata"
    namespace = "urn:meteor:partyvoicechannel"
    plugin_attrib = "partyvoicechannel"
    interfaces = set(("voiceurl"))
