# -*- coding: utf-8 -*-
# Hawken XMPP support
# Copyright (c) 2013-2014 Andrew Hampe

from sleekxmpp import Message
from sleekxmpp.plugins.base import base_plugin
from sleekxmpp.xmlstream import register_stanza_plugin
from sleekxmpp.xmlstream.handler import Callback
from sleekxmpp.xmlstream.matcher import StanzaPath
from hawkenapi.sleekxmpp.stanza import GameInvite


class Hawken(base_plugin):
    """
    Hawken Base Plugin
    """
    name = "hawken"
    description = "Hawken: Base Support"

    def plugin_init(self):
        # Register Stanzas
        register_stanza_plugin(Message, GameInvite)

        self.xmpp.register_handler(
            Callback("Hawken GameInvite",
                     StanzaPath("message@type=normal/invite"),
                     self._handle_gameinvite))

    def _handle_gameinvite(self, msg):
        self.xmpp.event("game_invite", msg)

    def game_invite(self, mto, mfrom):
        # Send an invite
        invite = self.xmpp.make_message(mto, mtype="normal")
        invite["invite"] = "Let's play HAWKEN?"
        invite.send()
