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

"""Main module."""

import sys
import json

from argparse import ArgumentParser

import tornado.ioloop

from empower_vbs_emulator.vbs import VBS


def main():
    """Main module."""

    # parse arguments
    parser = ArgumentParser()

    parser.add_argument("-a", "--address",
                        dest="address",
                        type=str,
                        default="127.0.0.1",
                        help="The 5G-EmPOWER runtime address")

    parser.add_argument("-p", "--port",
                        dest="port",
                        type=int,
                        default=5533,
                        help="The 5G-EmPOWER runtime port")

    parser.add_argument("-s", "--scenario",
                        dest="scenario",
                        type=str,
                        required=True,
                        help="Path to JSON file describing the scenario")

    parsed, _ = parser.parse_known_args(sys.argv[1:])

    scenario = {}

    # load json
    with open(parsed.scenario) as json_file:
        scenario = json.load(json_file)

    # instantiate VBS with configuration scenario
    vbs = VBS(address=parsed.address, port=parsed.port, scenario=scenario)

    # start VBS
    vbs.start()

    # start tornado loop
    tornado.ioloop.IOLoop.instance().start()
