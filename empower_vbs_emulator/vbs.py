#!/usr/bin/env python3
#
# Copyright (c) 2020 Roberto Riggio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""Emulated VBS."""

import time
import socket
import requests
import tornado.ioloop

from construct import Container
from tornado import gen
from tornado.tcpclient import TCPClient
from tornado.iostream import StreamClosedError

from empower_core.imsi import IMSI
from empower_core.plmnid import PLMNID
from empower_core.etheraddress import EtherAddress

import empower_vbs_emulator.vbsp as vbsp


class VBS:

    def __init__(self, address, port, scenario):

        self.read_chunk_size = 20

        # the tornado ioloop
        self.io_loop = tornado.ioloop.IOLoop.instance()

        # runtime
        self.address = address
        self.port = port

        # set scenario
        self.plmnid = scenario['plmnid']
        self.pci = scenario['pci']
        self.device = EtherAddress(scenario['device'])
        self.ues = scenario['ues']
        self.period = int(scenario['period'])

        # Worker process, set only if every > 0
        self.worker = None

        # The socket we will use for the connection to the runtime
        self.tcp_client = TCPClient()

        # The actual stream
        self.stream = None

        # The reading buffer
        self.buffer = b''

        # The sequence number
        self._seq = 0

        # The transaction number
        self._xid = 0

    @property
    def xid(self):
        """Return new xid."""

        self._xid += 1
        return self._xid

    @property
    def seq(self):
        """Return next sequence id."""

        self._seq += 1
        return self._seq

    def start(self):
        """Start the VBS."""

        print("+----------------------------------------------------+")
        print("Starting 5G-EmPOWER VBS Emulator")
        print("Device: %s" % self.device)
        print("PCI: %s" % self.pci)
        print("Period: %s" % self.period)
        print("Number of UEs: %s" % len(self.ues.keys()))
        print("+----------------------------------------------------+")

        # Start the control loop
        self.worker = \
            tornado.ioloop.PeriodicCallback(self.loop, self.period)

        self.worker.start()

    def wait(self):
        """ Wait for incoming packets on signalling channel """

        if not self.stream:
            return

        self.buffer = b''

        hdr_len = vbsp.HEADER.sizeof()

        future = self.stream.read_bytes(hdr_len)
        future.add_done_callback(self.on_read)

    def on_read(self, future):
        """Assemble message from agent.

        Appends bytes read from socket to a buffer. Once the full packet
        has been read the parser is invoked and the buffers is cleared. The
        parsed packet is then passed to the suitable method or dropped if the
        packet type in unknown.
        """

        try:
            self.buffer = self.buffer + future.result()
        except StreamClosedError as stream_ex:
            print(stream_ex)
            return

        hdr = vbsp.HEADER.parse(self.buffer)

        if len(self.buffer) < hdr.length:
            remaining = hdr.length - len(self.buffer)
            future = self.stream.read_bytes(remaining)
            future.add_done_callback(self.on_read)
            return

        # Check if we know the message type
        if hdr.tsrc.action not in vbsp.PT_TYPES:
            print("Unknown message type %u, ignoring." % hdr.tsrc.action)
            return

        # Check if the Device is among the ones we known
        addr = EtherAddress(hdr.device)

        if addr != self.device:
            print("Unknown device %s, closing connection." % addr)
            self.stream.close()
            return

        # Log message informations
        parser = vbsp.PT_TYPES[hdr.tsrc.action][0]
        name = vbsp.PT_TYPES[hdr.tsrc.action][1]
        msg = parser.parse(self.buffer)

        tmp = vbsp.decode_msg(hdr.flags.msg_type, hdr.tsrc.crud_result)

        print("Got %s message (%s, %s) from %s seq %u" %
              (name, tmp[0], tmp[1], EtherAddress(addr), msg.seq))

        # Handle message
        try:
            self.handle_message(name, msg)
        except Exception as ex:
            print(ex)
            self.stream.close()

        if not self.stream.closed():
            self.wait()

    def handle_message(self, method, msg):
        """Handle incoming message."""

        # If the default handler is defined then call it
        handler_name = "_handle_%s" % method
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            handler(msg)

    def _handle_capabilities_service(self, msg):
        """Handle capabilities request message."""

        self.send_capabilities_service()

    def send_capabilities_service(self):
        """Send an capabilities response message."""

        tlv = Container()
        tlv.pci = 0
        tlv.dl_earfcn = 0
        tlv.ul_earfcn = 0
        tlv.n_prbs = 0

        value = vbsp.CAPABILITIES_SERVICE_CELL.build(tlv)

        tlv = Container()
        tlv.type = vbsp.PT_CAPABILITIES_SERVICE_CELL
        tlv.length = 4 + len(value)
        tlv.value = value

        return self.send_message(action=vbsp.PT_CAPABILITIES_SERVICE,
                                 msg_type=vbsp.MSG_TYPE_RESPONSE,
                                 crud_result=vbsp.RESULT_SUCCESS,
                                 tlvs=[tlv])

    def on_disconnect(self):
        """Handle ctrl disconnection."""

        print("Ctrl disconnected")

        # The socket we will use for the connection to the runtime
        self.tcp_client = TCPClient()

        # The actual stream
        self.stream = None

        # The reading buffer
        self.buffer = b''

    @gen.coroutine
    def connect(self):
        """Connect to runtime."""

        if self.stream:
            return True

        # Establish a connection to the runtime
        print("Attemping to connect to %s:%u" % (self.address, self.port))

        try:

            # Try to connect
            self.stream = \
                yield self.tcp_client.connect(self.address, self.port)
            self.stream.set_nodelay(True)
            self.stream.set_close_callback(self.on_disconnect)

            # Wait for data
            self.wait()

        except StreamClosedError:
            self.stream = None
            print("Ctrl not available, retrying in %u ms" % self.period)
            return False

        return True

    def loop(self):
        """The periodic VBS loop, it basically just send the hello."""

        if not self.connect():
            return

        # Send hello
        self.send_hello()

    def send_hello(self):
        """Send a HELLO message."""

        return self.send_message(action=vbsp.PT_HELLO_SERVICE,
                                 msg_type=vbsp.MSG_TYPE_REQUEST,
                                 crud_result=vbsp.OP_UNDEFINED)

    def send_message(self, action, msg_type, crud_result, tlvs=None):
        """Send message and set common parameters."""

        parser = vbsp.PT_TYPES[action][0]
        name = vbsp.PT_TYPES[action][1]

        if not self.stream or self.stream.closed():
            print("Stream closed, unabled to send %s message to %s" %
                  (name, self.device))
            return 0

        msg = Container()

        msg.version = vbsp.PT_VERSION
        msg.flags = Container(msg_type=msg_type)
        msg.tsrc = Container(
            crud_result=crud_result,
            action=action
        )
        msg.length = vbsp.HEADER.sizeof()
        msg.padding = 0
        msg.device = self.device.to_raw()
        msg.seq = self.seq
        msg.xid = self.xid
        msg.tlvs = []

        if not tlvs:
            tlvs = []

        for tlv in tlvs:
            msg.tlvs.append(tlv)
            msg.length += tlv.length

        addr = self.stream.socket.getpeername()

        tmp = vbsp.decode_msg(msg_type, crud_result)

        print("Sending %s message (%s, %s) to %s seq %u" %
              (name, tmp[0], tmp[1], addr[0], msg.seq))

        self.stream.write(parser.build(msg))

        return msg.xid
