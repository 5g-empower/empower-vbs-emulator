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

import tornado.ioloop

from construct import Container
from tornado import gen
from tornado.tcpclient import TCPClient
from tornado.iostream import StreamClosedError

from empower_core.imsi import IMSI
from empower_core.plmnid import PLMNID
from empower_core.etheraddress import EtherAddress

import empower_vbs_emulator.vbsp as vbsp

from empower_vbs_emulator.user import User, USER_STATUS_CONNECTED, \
    USER_STATUS_DISCONNECTED
from empower_vbs_emulator.measurement import Measurement


class VBS:
    """Emulated Virtual Base Station."""

    def __init__(self, address, port, scenario):

        self.read_chunk_size = 20

        # the tornado ioloop
        self.io_loop = tornado.ioloop.IOLoop.instance()

        # runtime
        self.address = address
        self.port = port

        # The sequence number
        self._seq = 0

        # The transaction number
        self._xid = 0

        # The next RNTI
        self._rnti = 70

        # The active users
        self.users = {}

        # The cells in this VBS
        self.cells = {}

        # The cells in this VBS
        self.events = []

        # set scenario
        print("Setting 5G-EmPOWER VBS Emulator...")

        self.plmnid = PLMNID(scenario['plmnid'])
        self.device = EtherAddress(scenario['device'])
        self.period = int(scenario['period'])

        print("PLMNID: %s" % self.plmnid)
        print("Device: %s" % self.device)
        print("Period: %s" % self.period)

        for cell in scenario['cells'].values():
            self.add_cell(cell)

        print("Saving events descriptor")
        self.events_desc = scenario['events']

        # Worker process, set only if every > 0
        self.worker = None

        # The socket we will use for the connection to the runtime
        self.tcp_client = TCPClient()

        # The actual stream
        self.stream = None

        # The reading buffer
        self.buffer = b''

        # Set when the VBS is connected
        self.connected = False

        # The callback for the events
        self.event_callback = None

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

    @property
    def rnti(self):
        """Return next rnti."""

        self._rnti += 1
        return self._rnti

    def add_event(self, event):
        """Add a new event."""

        new_event = {
            "type": event['type'],
            "delay": int(event['delay']),
            "payload": event["payload"]
        }

        print("Adding event %s delay %u" % (new_event['type'],
              new_event['delay']))

        self.events.append(new_event)

    def add_user(self, user):
        """Add a new UE."""

        imsi = IMSI(user['imsi'])
        tmsi = int(user['tmsi'])
        rnti = self.rnti

        print("Adding UE (IMSI=%s, TMSI=%u, RNTI=%u)" % (imsi, tmsi, rnti))

        pci = int(user['pci'], 16)
        cell = self.cells[pci]

        user = User(imsi, tmsi, rnti, cell, self, USER_STATUS_CONNECTED)

        self.users[imsi] = user
        user.start()

        self.send_ue_reports_service()

    def rem_user(self, user):
        """Remove a UE."""

        imsi = IMSI(user['imsi'])

        print("Removing UE (IMSI=%s)" % imsi)

        self.users[imsi].status = USER_STATUS_DISCONNECTED

        self.send_ue_reports_service()

        self.users[imsi].stop()
        del self.users[imsi]

    def add_cell(self, cell):
        """Add a new Cell."""

        pci = int(cell['pci'], 16)
        dl_earfcn = int(cell['dl_earfcn'])
        ul_earfcn = int(cell['ul_earfcn'])
        n_prbs = int(cell['n_prbs'])

        print("Adding Cell (PCI=%u, PRBs=%u)" % (pci, n_prbs))

        self.cells[pci] = {
            'pci': pci,
            'dl_earfcn': dl_earfcn,
            'ul_earfcn': ul_earfcn,
            'n_prbs': n_prbs
        }

    def start(self):
        """Start the VBS."""

        print("Starting 5G-EmPOWER VBS Emulator...")

        # Start the control loop
        self.worker = \
            tornado.ioloop.PeriodicCallback(self.loop, self.period)

        self.worker.start()

    def schedule_next_event(self):
        """Execute next event in the queue."""

        if not self.events:
            return

        event = self.events.pop()

        if event['type'] == "ue_join":
            self.add_user(event['payload'])
        elif event['type'] == "ue_leave":
            self.rem_user(event['payload'])
        else:
            print("Event %s not supported" % event['type'])

        # Schedule first event
        if self.events:
            delay = self.events[-1]['delay']
            self.io_loop.call_later(delay=delay / 1000,
                                    callback=self.schedule_next_event)

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

    def _handle_capabilities_service(self, _):
        """Handle capabilities request message."""

        print("Sending capabilities...")

        # Answer request
        self.send_capabilities_service()

        # VBS is now fully connected
        self.connected = True

        # Reset events
        print("Importing %u events..." % len(self.events_desc))
        self.events = []

        # Import events from descriptor
        for event in self.events_desc:
            self.add_event(event)

        self.events.reverse()

        # Start processing events
        if self.events:
            delay = self.events[-1]['delay']
            self.event_callback = \
                self.io_loop.call_later(delay=delay / 1000,
                                        callback=self.schedule_next_event)

    def _handle_ue_reports_service(self, _):
        """Handle ue reports request message."""

        self.send_ue_reports_service()

    def _handle_ue_measurements_service(self, msg):
        """Handle ue measurements request message."""

        # if not a response then ignore
        if msg.flags.msg_type != vbsp.MSG_TYPE_REQUEST:
            print("Not a request, ignoring.")
            return

        # there should be only one tlv
        for tlv in msg.tlvs:

            if tlv.type == vbsp.TLV_MEASUREMENTS_SERVICE_CONFIG:

                parser = vbsp.TLVS[tlv.type]
                option = parser.parse(tlv.value)

                for user in self.users.values():

                    if user.rnti != option.rnti:
                        continue

                    meas = Measurement(option.rnti, option.meas_id,
                                       option.interval, option.amount,
                                       user)

                    if msg.tsrc.crud_result == vbsp.OP_CREATE:
                        user.ue_measurements[option.meas_id] = meas
                        meas.start()
                    else:
                        print("Service config operation unsupported")

    def send_capabilities_service(self):
        """Send a capabilities response message."""

        tlvs = []

        for cell in self.cells.values():

            tlv = Container()
            tlv.pci = cell['pci']
            tlv.dl_earfcn = cell['dl_earfcn']
            tlv.ul_earfcn = cell['ul_earfcn']
            tlv.n_prbs = cell['n_prbs']

            value = vbsp.CAPABILITIES_SERVICE_CELL.build(tlv)

            tlv = Container()
            tlv.type = vbsp.PT_CAPABILITIES_SERVICE_CELL
            tlv.length = 4 + len(value)
            tlv.value = value

            tlvs.append(tlv)

        return self.send_message(action=vbsp.PT_CAPABILITIES_SERVICE,
                                 msg_type=vbsp.MSG_TYPE_RESPONSE,
                                 crud_result=vbsp.RESULT_SUCCESS,
                                 tlvs=tlvs)

    def send_ue_reports_service(self):
        """Send a ue reports message."""

        tlvs = []

        for user in self.users.values():

            tlv = Container()
            tlv.imsi = int(user.imsi.to_str())
            tlv.tmsi = user.tmsi
            tlv.rnti = user.rnti
            tlv.status = user.status
            tlv.pci = user.cell['pci']

            value = vbsp.UE_REPORTS_SERVICE_IDENTITY.build(tlv)

            tlv = Container()
            tlv.type = vbsp.PT_UE_REPORTS_SERVICE_IDENTITY
            tlv.length = 4 + len(value)
            tlv.value = value

            tlvs.append(tlv)

        return self.send_message(action=vbsp.PT_UE_REPORTS_SERVICE,
                                 msg_type=vbsp.MSG_TYPE_RESPONSE,
                                 crud_result=vbsp.RESULT_SUCCESS,
                                 tlvs=tlvs)

    def send_ue_measurements(self, rnti, meas_id, rsrp, rsrq):
        """Send a ue reports message."""

        tlvs = []

        tlv = Container()
        tlv.rnti = rnti
        tlv.meas_id = meas_id
        tlv.rsrp = rsrp
        tlv.rsrq = rsrq

        value = vbsp.UE_MEASUREMENTS_SERVICE_REPORT.build(tlv)

        tlv = Container()
        tlv.type = vbsp.TLV_MEASUREMENTS_SERVICE_REPORT
        tlv.length = 4 + len(value)
        tlv.value = value

        tlvs.append(tlv)

        return self.send_message(action=vbsp.PT_UE_MEASUREMENTS_SERVICE,
                                 msg_type=vbsp.MSG_TYPE_RESPONSE,
                                 crud_result=vbsp.RESULT_SUCCESS,
                                 tlvs=tlvs)

    def on_disconnect(self):
        """Handle ctrl disconnection."""

        print("Ctrl disconnected")

        # The socket we will use for the connection to the runtime
        self.tcp_client = TCPClient()

        # The actual stream
        self.stream = None

        # The reading buffer
        self.buffer = b''

        # Set when the VBS is connected
        self.connected = False

        # Remove callback
        self.io_loop.remove_timeout(self.event_callback)

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
