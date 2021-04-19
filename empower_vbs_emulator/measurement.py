#!/usr/bin/env python3
#
# Copyright (c) 2019 Roberto Riggio
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

"""UE Measurement."""

import enum
import csv

import tornado.ioloop

from empower_core.serialize import serializable_dict


class RRCReportInterval(enum.Enum):
    MS120 = 0
    MS240 = 1
    MS480 = 2
    MS640 = 3
    MS1024 = 4
    MS2048 = 5
    MS5120 = 6
    MS10240 = 7
    MIN1 = 8
    MIN6 = 9
    MIN12 = 10
    MIN30 = 11
    MIN60 = 12


class RRCReportAmount(enum.Enum):
    R1 = 0
    R2 = 1
    R4 = 2
    R8 = 3
    R16 = 4
    R32 = 5
    R64 = 6
    INFINITY = 7


@serializable_dict
class Measurement():
    """User Equipment

    Attributes:
        rnti: the UE RNTI
        meas_id: the measurement it
        interval: the measurement interval
        amount: the measurement amount (ignored for now)
    """

    def __init__(self, rnti, meas_id, interval, amount, user):

        # measurement data
        self.rnti = rnti
        self.meas_id = meas_id
        self.interval = interval
        self.amount = amount

        # the user to which this measurement is linked
        self.user = user

        # the tornado ioloop
        self.io_loop = tornado.ioloop.IOLoop.instance()

        # worker
        self.worker = None

        # sample points
        self.samples = []

        # sample idx
        self.sample_idx = 0

    def start(self):
        """Start measurement tasks."""

        print("Starting measurement %s" % self)

        interval = RRCReportInterval(self.interval)
        amount = RRCReportAmount(self.amount)

        if interval == RRCReportInterval.MS120:
            interval = 120
        elif interval == RRCReportInterval.MS240:
            interval = 240
        elif interval == RRCReportInterval.MS480:
            interval = 480
        elif interval == RRCReportInterval.MS640:
            interval = 640
        elif interval == RRCReportInterval.MS1024:
            interval = 1024
        elif interval == RRCReportInterval.MS2048:
            interval = 2048
        elif interval == RRCReportInterval.MS5120:
            interval = 5120
        elif interval == RRCReportInterval.MS10240:
            interval = 10240
        elif interval == RRCReportInterval.MIN1:
            interval = 1 * 60 * 1000
        elif interval == RRCReportInterval.MIN6:
            interval = 6 * 60 * 1000
        elif interval == RRCReportInterval.MIN12:
            interval = 12 * 60 * 1000
        elif interval == RRCReportInterval.MIN30:
            interval = 30 * 60 * 1000
        elif interval == RRCReportInterval.MIN60:
            interval = 60 * 60 * 1000
        else:
            raise ValueError("Measurement interval not supported %u" %
                             self.interval)

        print("Reporting interval %u ms" % interval)
        print("Amount %s" % amount)

        # Start the control loop
        self.worker = \
            tornado.ioloop.PeriodicCallback(self.loop, interval)

        self.worker.start()

        # load trace
        self.samples = []
        with open(self.user.trace) as csvfile:
            reader = csv.DictReader(csvfile, delimiter=';')
            for row in reader:
                self.samples.append(row)

    def stop(self):
        """Stop measurement tasks."""

        print("Stopping measurement %s" % self)

        if self.worker:
            self.worker.stop()

    def loop(self):
        """Periodic loop."""

        sample = self.samples[self.sample_idx]

        # use the same format an eNB would use
        rsrp = int(sample['rsrp']) + 140
        rsrq = int((int(sample['rsrq']) + 19.5) * 2)

        self.sample_idx = (self.sample_idx + 1) % len(self.samples)

        self.user.vbs.send_ue_measurements(self.rnti, self.meas_id, rsrp, rsrq)

    def to_dict(self):
        """Return JSON-serializable representation of the object."""

        out = dict()
        out['rnti'] = self.rnti
        out['meas_id'] = self.meas_id
        out['interval'] = self.interval
        out['amount'] = self.amount
        return out

    def to_str(self):
        """Return an ASCII representation of the object."""

        return "rnti=%u, meas_id=%u" % (self.rnti, self.meas_id)

    def __str__(self):
        return self.to_str()

    def __hash__(self):
        return hash(self.meas_id)

    def __eq__(self, other):
        if isinstance(other, Measurement):
            return self.rnti == other.rnti and self.meas_id == other.meas_id
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return self.__class__.__name__ + "('" + self.to_str() + "')"
