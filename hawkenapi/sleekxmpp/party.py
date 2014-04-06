# -*- coding: utf-8 -*-

from enum import Enum
from sleekxmpp import Message
from sleekxmpp.plugins.base import base_plugin
from sleekxmpp.xmlstream import register_stanza_plugin
from sleekxmpp.xmlstream.handler import Callback
from sleekxmpp.xmlstream.matcher import StanzaPath
from hawkenapi.sleekxmpp.stanza import StormId, PartyMemberData, PartyVoiceChannel, MemberDataCodes


class CancelCode(str, Enum):
    none = "0"
    leader_action = "1"
    leader_change = "2"
    match_failure = "3"
    member_join = "4"
    member_left = "5"
    member_kicked = "6"


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

        # Register Handler
        self.xmpp.register_handler(
            Callback("Hawken PartyMemberData",
                     StanzaPath("message@type=groupchat/partymemberdata"),
                     self._handle_partymemberdata))

    def plugin_end(self):
        self.xmpp.remove_handler("Hawken PartyMemberData")

    def _party_notice(self, room, sender, name, value):
        # Build the party notice
        message = self.xmpp.make_message(room, mtype="groupchat", mfrom=sender.bare)
        message["partymemberdata"]["infoName"] = name
        message["partymemberdata"]["playerId"] = sender.user
        message["partymemberdata"]["infoValue"] = value

        # Send invite notification
        message.send()

    def _handle_partymemberdata(self, msg):
        self.xmpp.event("groupchat_partymemberdata", msg)
        self.xmpp.event("muc::%s::partymemberdata" % msg["from"].bare, msg)

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
        return self.xmpp.plugin["xep_0045"].api["get_self_nick"](self.xmpp.boundjid, room)

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
        self.xmpp.plugin["xep_0045"].invite(room, target, reason=reason, mfrom=sender.bare, mediated=True)

        # Send invite notification
        value = "{0} has invited {1} to the party.".format(self.get_callsign(room), callsign)
        self._party_notice(room, sender, MemberDataCodes.invite_player, value)

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
        self.xmpp.plugin["xep_0045"].set_affiliation(room, target, "owner", block=True)

    def matchmaking_start(self, room, sender):
        # Send matchmaking start notice
        self._party_notice(room, sender, MemberDataCodes.matchmaking_start, "NoData")

    def matchmaking_cancel(self, room, sender, code=CancelCode.none):
        # Send matchmaking cancel notice
        self._party_notice(room, sender, MemberDataCodes.matchmaking_cancel, code)

    def deploy_start(self, room, sender, countdown):
        # Send deploy start notice
        self._party_notice(room, sender, MemberDataCodes.deploy_party, str(countdown))

    def deploy_cancel(self, room, sender, code=CancelCode.none):
        # Send deploy cancel notice
        self._party_notice(room, sender, MemberDataCodes.deploy_cancel, code)

    def travel_request(self, room, sender, guid, ip, port, has_reservation):
        if has_reservation:
            has_reservation = "1"
        else:
            has_reservation = "0"

        # Send travel request notice
        self._party_notice(room, sender, MemberDataCodes.travel_request, ";".join((guid, ip, str(port), has_reservation)))

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
