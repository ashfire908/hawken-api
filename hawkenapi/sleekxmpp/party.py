# -*- coding: utf-8 -*-

from sleekxmpp import Message
from sleekxmpp.plugins.base import base_plugin
from sleekxmpp.xmlstream import register_stanza_plugin, ET
from hawkenapi.sleekxmpp.stanza import StormId, PartyMemberData, PartyVoiceChannel, MemberDataCodes
from hawkenapi.util import enum


CancelCode = enum(PARTYCANCEL="0", LEADERCANCEL="1", LEADERCHANGE="2", NOMATCH="3", MEMBERJOIN="4", MEMBERLEFT="5", MEMBERKICK="6")


class Hawken_Party(base_plugin):
    """
    Hawken Party Plugin
    """
    name = "hawken_party"
    description = "Hawken: Party Support"
    dependencies = {"xep_0004", "xep_0045"}

    def plugin_init(self):
        # Register Stanzas
        register_stanza_plugin(Message, StormId)
        register_stanza_plugin(Message, PartyMemberData)
        register_stanza_plugin(Message, PartyVoiceChannel)

    def _party_notice(self, room, sender, name, value):
        # Build the party notice
        message = self.xmpp.make_message(room, mtype="groupchat", mfrom=sender.bare)
        message["partymemberdata"]["infoName"] = name
        message["partymemberdata"]["playerId"] = sender.user
        message["partymemberdata"]["infoValue"] = value

        # Send invite notification
        message.send()

    def get_joined_rooms(self):
        # Get joined rooms
        return self.xmpp.plugin["xep_0045"].api["get_joined_rooms"](self.xmpp.boundjid, None)

    def create(self, room, callsign):
        # Join the room
        self.xmpp.plugin["xep_0045"].join(room, callsign)

        # Create the room config
        config = self.xmpp.plugin["xep_0004"].make_form(ftype="submit")
        config.add_field(var="muc#roomconfig_publicroom", ftype="boolean", value="0")
        config.add_field(var="muc#roomconfig_allowinvites", ftype="boolean", value="1")
        config.add_field(var="muc#roomconfig_gametype", ftype="text-single", value="Game")

        # Configure the room
        self.xmpp.plugin["xep_0045"].set_room_config(room, config)

    def join(self, room, callsign):
        # Join the room
        self.xmpp.plugin["xep_0045"].join(room, callsign)

    def leave(self, room):
        # Leave the room
        self.xmpp.plugin["xep_0045"].leave(room)

    def destroy(self, room, reason=None):
        # Destroy the room
        self.xmpp.plugin["xep_0045"].destroy(room, reason=reason)

    def get_callsign(self, room):
        # Get our callsign
        return self.xmpp.plugin["xep_0045"].api['get_self_nick'](self.xmpp.boundjid, room)

    def set_callsign(self, room, callsign):
        # Set our callsign
        return self.xmpp.plugin["xep_0045"].change_nick(room, callsign)

    def message(self, room, sender, body):
        # Build the message
        message = self.xmpp.make_message(mto=room, mtype="groupchat", mfrom=sender.bare)
        message["body"] = body
        message["stormid"] = sender.user

        # Send party message
        message.send()

    def invite(self, room, sender, target, callsign, reason=None):
        # Send the invite to the player
        # Game client does not recognize this invite type
        #self.xmpp.plugin["xep_0045"].invite(room, target, reason=reason, mfrom=sender.bare)

        # Manually create the invite
        msg = self.xmpp.make_message(mto=room, mfrom=sender.bare)
        x = ET.Element('{http://jabber.org/protocol/muc#user}x')
        invite = ET.Element('{http://jabber.org/protocol/muc#user}invite', {'to': target})
        if reason:
            rxml = ET.Element('{http://jabber.org/protocol/muc#user}reason')
            rxml.text = reason
            invite.append(rxml)
        x.append(invite)
        msg.append(x)
        nick = ET.Element('{http://jabber.org/protocol/nick}nick')
        nick.text = self.get_callsign(room)
        msg.append(nick)
        self.xmpp.send(msg)

        # Send invite notification
        value = "{0} has invited {1} to the party.".format(self.get_callsign(room), callsign)
        self._party_notice(room, sender, MemberDataCodes.InvitePlayer, value)

    def kick(self, room, callsign, reason=None):
        # Kick the user
        self.xmpp.plugin["xep_0045"].kick(room, callsign)

    def ban(self, room, target, reason=None):
        # Ban the user
        self.xmpp.plugin["xep_0045"].ban(room, target, reason=reason)

    def unban(self, room, target, reason=None):
        # Check if the user is actually banned
        banned_users = self.xmpp.plugin["xep_0045"].get_users(room, affiliation="outcast")
        if target is not banned_users:
            # Unban the user
            self.xmpp.plugin["xep_0045"].set_affiliation(room, target, "none")
            return True

        return False

    def get_leader(self, room):
        # Search the roster for the owner
        roster = self.xmpp.plugin["xep_0045"].get_roster(room)
        if roster is not None:
            for nick, data in roster.items():
                if data["muc"]["affiliation"] == "owner":
                    return nick

        return None

    def set_leader(self, room, target):
        # Set the target as the owner
        self.xmpp.plugin["xep_0045"].set_affiliation(room, target, "owner")

    def matchmaking_start(self, room, sender):
        # Send matchmaking start notice
        self._party_notice(room, sender, MemberDataCodes.MatchmakingStart, "NoData")

    def matchmaking_cancel(self, room, sender, code=CancelCode.PARTYCANCEL):
        # Send matchmaking cancel notice
        self._party_notice(room, sender, MemberDataCodes.MatchmakingCancel, code)

    def deploy_start(self, room, sender, server):
        # Send deploy start notice
        self._party_notice(room, sender, MemberDataCodes.DeployParty, server)

    def deploy_cancel(self, room, sender, code=CancelCode.PARTYCANCEL):
        # Send deploy cancel notice
        self._party_notice(room, sender, MemberDataCodes.DeployCancel, code)

    def game_start(self, room):
        # Create room config for update
        config = self.xmpp.plugin["xep_0004"].make_form(ftype="submit")
        config.add_field(var="muc#roomconfig_gametype", ftype="text-single", value="Hawken")

        # Reconfigure the room
        self.xmpp.plugin["xep_0045"].set_room_config(room, config)

    def game_end(self, room):
        # Create room config for update
        config = self.xmpp.plugin["xep_0004"].make_form(ftype="submit")
        config.add_field(var="muc#roomconfig_gametype", ftype="text-single", value="Game")

        # Reconfigure the room
        self.xmpp.plugin["xep_0045"].set_room_config(room, config)
