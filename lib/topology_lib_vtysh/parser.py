# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Parse vtysh commands with output to a python dictionary.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

import re


def parse_show_interface_mgmt(raw_result):
    """
    Parse the 'show interface mgmt' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface mgmt command in a \
        dictionary of the form:

     ::

        {
            'address_mode': 'dhcp',
            'ipv4': '20.1.1.2/30',
            'default_gateway_ipv4': '20.1.1.1',
            'ipv6': '2011::2/64',
            'ipv6_link_local': 'fe80::4a0f:cfff:feaf:6358/64',
            'default_gateway_ipv6': '2011::1',
            'primary_nameserver': '232.54.54.54',
            'secondary_nameserver': '232.54.54.44'
       }
    """

    show_re = (
        r'\s*Address Mode\s*:\s*(?P<address_mode>\S+)\s*'
        r'\s*IPv4 address/subnet-mask\s*:\s*(?P<ipv4>[0-9./]+)?\s*'
        r'\s*Default gateway IPv4\s*:\s*(?P<default_gateway_ipv4>[0-9.]+)?\s*'
        r'\s*IPv6 address/prefix\s*:\s*(?P<ipv6>[0-9a-f:/]+)?\s*'
        r'\s*IPv6 link local address/prefix\s*:\s*'
        r'(?P<ipv6_link_local>[0-9a-f:/]+)?\s*'
        r'\s*Default gateway IPv6\s*:\s*'
        r'(?P<default_gateway_ipv6>[0-9a-f:]+)?\s*'
        r'\s*Primary Nameserver\s*:\s*(?P<primary_nameserver>[0-9.]+)?\s*'
        r'\s*Secondary Nameserver\s*:\s*(?P<secondary_nameserver>[0-9.]+)?\s*'
    )

    re_result = re.match(show_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    return result


def parse_show_interface(raw_result):
    """
    Parse the 'show interface' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface command in a \
        dictionary of the form:

     ::

        {
            'admin_state': 'down',
            'autonegotiation': True,
            'conection_type': 'Half-duplex',
            'hardware': 'Ethernet',
            'input_flow_control': False,
            'interface_state': 'down',
            'mac_address': '70:72:cf:d7:d3:dd',
            'mtu': 0,
            'output_flow_control': False,
            'port': 7,
            'rx_crc_fcs': 0,
            'rx_dropped': 0,
            'rx_bytes': 0,
            'rx_error': 0,
            'rx_packets': 0,
            'speed': 0,
            'speed_unit': 'Mb/s',
            'state_description': 'Administratively down',
            'state_information': 'admin_down',
            'tx_bytes': 0,
            'tx_collisions': 0,
            'tx_dropped': 0,
            'tx_errors': 0,
            'tx_packets': 0
            'ipv4': '20.1.1.2/30'
        }
    """
    if 'lag' in raw_result:
        return parse_show_interface_lag(raw_result)

    show_re = (
        r'\s*Interface (?P<port>\w+) is (?P<interface_state>\S+)\s*'
        r'(\((?P<state_description>.*)\))?\s*'
        r'Admin state is (?P<admin_state>\S+)\s+'
        r'(State information: (?P<state_information>\S+))?\s*'
        r'Hardware: (?P<hardware>\S+), MAC Address: (?P<mac_address>\S+)\s+'
        r'(IPv4 address (?P<ipv4>\S+))?\s*'
        r'(IPv4\saddress\s(?P<ipv4_secondary>\S+) secondary)?\s*'
        r'(IPv6 address (?P<ipv6>\S+))?\s*'
        r'(IPv6\saddress\s(?P<ipv6_secondary>\S+) secondary)?\s*'
        r'MTU (?P<mtu>\d+)\s+'
        r'(?P<conection_type>\S+)\s+'
        r'qos trust (?P<qos_trust>\S+)\s+'
        r'qos queue-profile (?P<qos_queue_profile>\S+)\s+'
        r'qos schedule-profile (?P<qos_schedule_profile>\S+)\s+'
        r'Speed (?P<speed>\d+) (?P<speed_unit>\S+)\s+'
        r'Auto-Negotiation is turned (?P<autonegotiation>\S+)\s+'
        r'Input flow-control is (?P<input_flow_control>\w+),\s+'
        r'output flow-control is (?P<output_flow_control>\w+)\s+'
        r'RX\s+'
        r'(?P<rx_packets>\d+) input packets\s+'
        r'(?P<rx_bytes>\d+) bytes\s+'
        r'(?P<rx_error>\d+) input error\s+'
        r'(?P<rx_dropped>\d+) dropped\s+'
        r'(?P<rx_crc_fcs>\d+) CRC/FCS\s+'
        r'(L3:)?'
        r'(\s*ucast:\s+(?P<rx_l3_ucast_packets>\d+) packets,)?\s*'
        r'((?P<rx_l3_ucast_bytes>\d+) bytes)?'
        r'(\s*mcast:\s+(?P<rx_l3_mcast_packets>\d+) packets,)?\s+'
        r'((?P<rx_l3_mcast_bytes>\d+) bytes\s+)?'
        r'TX\s+'
        r'(?P<tx_packets>\d+) output packets\s+'
        r'(?P<tx_bytes>\d+) bytes\s+'
        r'(?P<tx_errors>\d+) input error\s+'
        r'(?P<tx_dropped>\d+) dropped\s+'
        r'(?P<tx_collisions>\d+) collision'
        r'(\s*L3:)?'
        r'(\s*ucast:\s+(?P<tx_l3_ucast_packets>\d+) packets,\s+)?'
        r'((?P<tx_l3_ucast_bytes>\d+) bytes)?'
        r'(\s*mcast:\s+(?P<tx_l3_mcast_packets>\d+) packets,\s+)?'
        r'((?P<tx_l3_mcast_bytes>\d+) bytes)?'
    )

    re_result = re.match(show_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if value.isdigit():
                result[key] = int(value)
            elif value == 'on':
                result[key] = True
            elif value == 'off':
                result[key] = False
            else:
                result[key] = value
    return result


def parse_show_interface_lag(raw_result):
    """
    Parse the 'show interface' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface command in a \
        dictionary of the form:

     ::

        {
            'lag_name': 'lag1',
            'aggregated_interfaces': '2 1',
            'agg_key': 1,
            'agg_mode': 'active'
            'ipv4': '10.1.1.1/24',
            'ipv4_secondary': '10.1.1.2/24',
            'ipv6': '2001::1/12',
            'ipv6_secondary': '2001::2/12',
            'speed': 0,
            'speed_unit': 'Mb/s',
            'rx_crc_fcs': 0,
            'rx_dropped': 0,
            'rx_bytes': 0,
            'rx_error': 0,
            'rx_packets': 0,
            'tx_bytes': 0,
            'tx_collisions': 0,
            'tx_dropped': 0,
            'tx_errors': 0,
            'tx_packets': 0,
        }
    """

    show_re = (
        r'\s*Aggregate-name\s(?P<lag_name>\w*)\s*'
        r'Aggregated-interfaces\s\:\s(?P<aggregated_interfaces>(\d\s)*)\s*'
        r'Aggregation-key\s:\s(?P<agg_key>\d*)\s*'
        r'(Aggregate mode\s:\s(?P<agg_mode>\S+))?\s*'
        r'(IPv4\saddress\s(?P<ipv4>\S+))?\s*'
        r'(IPv4\saddress\s(?P<ipv4_secondary>\S+) secondary)?\s*'
        r'(IPv6\saddress\s(?P<ipv6>\S+))?\s*'
        r'(IPv6\saddress\s(?P<ipv6_secondary>\S+) secondary)?\s*'
        r'Speed\s(?P<speed>\d+)\s(?P<speed_unit>\S+)\s*'
        r'RX\s*'
        r'(?P<rx_packets>\d+) input packets\s*'
        r'(?P<rx_bytes>\d+) bytes\s*'
        r'(?P<rx_error>\d+) input error\s*'
        r'(?P<rx_dropped>\d+) dropped\s*'
        r'(?P<rx_crc_fcs>\d+) CRC/FCS\s*'
        r'TX\s*'
        r'(?P<tx_packets>\d+) output packets\s*'
        r'(?P<tx_bytes>\d+) bytes\s*'
        r'(?P<tx_errors>\d+) input error\s*'
        r'(?P<tx_dropped>\d+) dropped\s*'
        r'(?P<tx_collisions>\d+) collision'
    )

    re_result = re.match(show_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if value.isdigit():
                result[key] = int(value)
            elif value == 'on':
                result[key] = True
            elif value == 'off':
                result[key] = False
    return result


def parse_show_interface_subinterface(raw_result):
    """
    Parse the 'show interface <port> subinterface' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface command in a \
        dictionary of the form:

     ::

        {
            '1': {'admin_state': 'down',
                  'encapsulation_dot1q': 102,
                  'hardware': 'Ethernet',
                  'input_flow_control': False,
                  'interface_state': 'down',
                  'mac_address': '70:72:cf:d7:d3:dd',
                  'output_flow_control': False,
                  'parent_interface': 2,
                  'port': 2,
                  'rx_mcast_packets': 0,
                  'rx_mcast_bytes': 0,
                  'rx_ucast_packets': 0,
                  'rx_ucast_bytes': 0,
                  'state_description': 'Administratively down',
                  'state_information': 'admin_down',
                  'subinterface': 1,
                  'tx_mcast_packets': 0,
                  'tx_mcast_bytes': 0,
                  'tx_ucast_packets': 0,
                  'tx_ucast_bytes': 0,
                  'ipv4': '20.1.1.2/30'},
            '2': {'admin_state': 'up',
                  'encapsulation_dot1q': 102,
                  'hardware': 'Ethernet',
                  'input_flow_control': False,
                  'interface_state': 'down',
                  'mac_address': '70:72:cf:d7:d3:dd',
                  'output_flow_control': False,
                  'parent_interface': 2,
                  'port': 2,
                  'rx_mcast_packets': 0,
                  'rx_mcast_bytes': 0,
                  'rx_ucast_packets': 0,
                  'rx_ucast_bytes': 0,
                  'state_description': 'Administratively down',
                  'state_information': 'admin_down',
                  'subinterface': 2,
                  'tx_mcast_packets': 0,
                  'tx_mcast_bytes': 0,
                  'tx_ucast_packets': 0,
                  'tx_ucast_bytes': 0,
                  'ipv4': '20.1.1.2/30'}
        }
    """

    show_re = (
        r'\s*Interface (?P<port>\d+)\.(?P<subinterface>\d+) is'
        r'\s*(?P<interface_state>\S+)\.(\s*)'
        r'(\((?P<state_description>.*)\))?\s*'
        r'Admin state is (?P<admin_state>\S+)\s+'
        r'(State information: (?P<state_information>\S+))?\s*'
        r'Parent interface is (?P<parent_interface>\d+)\s*'
        r'Encapsulation dot1Q (?P<encapsulation_dot1q>\d+)\s*'
        r'Hardware: (?P<hardware>\S+), MAC Address: (?P<mac_address>\S+)\s+'
        r'(IPv4 address (?P<ipv4>\S+))?\s*'
        r'(IPv6 address (?P<ipv6>\S+))?\s*'
        r'Input flow-control is (?P<input_flow_control>\w+),\s+'
        r'output flow-control is (?P<output_flow_control>\w+)\s+'
        r'RX\s+'
        r'\s*L3:'
        r'\s*ucast:\s+(?P<rx_ucast_packets>\d+) packets,\s*'
        r'(?P<rx_ucast_bytes>\d+) bytes'
        r'\s*mcast:\s+(?P<rx_mcast_packets>\d+) packets,\s+'
        r'(?P<rx_mcast_bytes>\d+) bytes\s+'
        r'TX\s+'
        r'\s*L3:'
        r'\s*ucast:\s+(?P<tx_ucast_packets>\d+) packets,\s+'
        r'(?P<tx_ucast_bytes>\d+) bytes'
        r'\s*mcast:\s+(?P<tx_mcast_packets>\d+) packets,\s+'
        r'(?P<tx_mcast_bytes>\d+) bytes\s*'
    )
    subint_list = raw_result.split("Interface")
    result = {}
    for subint in subint_list:
        if subint != "":
            subint = "Interface{}".format(subint)
            re_result = re.match(show_re, subint)
            assert re_result
            subint_result = re_result.groupdict()
            for key, value in subint_result.items():
                if value is not None:
                    if value.isdigit():
                        subint_result[key] = int(value)
                    elif value == 'on':
                        subint_result[key] = True
                    elif value == 'off':
                        subint_result[key] = False
            result[subint_result['subinterface']] = subint_result
    return result


def parse_show_mac_address_table(raw_result):
    """
    Parse the 'show mac-address table' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show mac-address-table command in a \
        dictionary of the form:

     ::

        {
            ':00:00:00:00:00:01': { 'vlan_id': '1',
                                    'from': 'dynamic',
                                    'port': '1'
            },
            ':00:00:00:00:00:02': { 'vlan_id': '2',
                                    'from': 'dynamic',
                                    'port': '2'
            }

        }
    """
    table_global = (
        r'\s*MAC\s*age-time\s*:\s*(?P<age_time>[0-9]+)'
        r'\s*seconds\s*\n'
        r'\s*Number\s*of\s*MAC\s*addresses\s*:'
        r'\s*(?P<no_mac_address>[0-9]+)\s*\n'
    )
    mac_entry = (
        r'(?P<mac>:([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\s*'
        r'(?P<vlan_id>[0-9]+)\s*'
        r'(?P<from>[- a-zA-Z]+)\s*(?P<port>\w+)'
    )

    result = {}
    re_result = re.search(table_global, raw_result)
    if re_result:
        result = re_result.groupdict()

    for line in raw_result.splitlines():
        mac_result = re.search(mac_entry, line)
        if mac_result:
            partial = mac_result.groupdict()
            partial['from'] = partial['from'].strip()
            mac = partial['mac']
            del partial['mac']
            result[mac] = partial

    return result


def parse_show_udld_interface(raw_result):
    """
    Parse the 'show udld interface {intf}' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show udld command in a \
        dictionary of the form:

     ::

        {
            'interface': '1',
            'status': 'Unblock',
            'mode': 'Verify then forward',
            'interval': 3000,
            'retries': 10,
            'port_transition': 0,
            'rx': 0,
            'rx_discard': 0,
            'tx': 0,
        }

    This is the current output of "show udld interface 1":

    switch# show udld interface 1

    Interface 1
     Status: Not running
     Mode: Verify then forward
     Interval: 5000 milliseconds
     Retries: 4
     Port transitions: 0
     RX: 0 valid packets, 0 discarded packets
     TX: 0 packets
    """

    show_re = (
        r'\s*Interface (?P<interface>.*)\n'
        r' Status: (?P<status>.*)\n'
        r' Mode: (?P<mode>.*)\n'
        r' Interval: (?P<interval>\d+) milliseconds\n'
        r' Retries: (?P<retries>\d+)\n'
        r' Port transitions: (?P<port_transition>\d+)\n'
        r' RX: (?P<rx>\d+) valid packets, (?P<rx_discard>\d+) discarded.*\n'
        r' TX: (?P<tx>\d+) packets$'
    )

    re_result = re.match(show_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            # The interface may be a digit (e.g '1') or string ('fast0/1')
            if value.isdigit() and key != 'interface':
                result[key] = int(value)
    return result


def parse_show_interface_loopback(raw_result):
    """
    Parse the 'show interface loopback' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface loopback command in a \
        dictionary of the form:

     ::

      'lo2':
          {'AdminState': 'up',
           'ipv6_address': '2001::2/64',
           'ipv4_address': '10.0.0.1/24'},
      'lo4':
          {'AdminState': 'up',
           'ipv6_address': '2002::1/64',
           'ipv4_address': '192.168.1.1/24'}

    """
    result = {}
    loopback_list = []
    show_loopback_id = re.compile('lo[0-9]+', re.DOTALL)
    loopback_list = show_loopback_id.findall(raw_result)
    if loopback_list:
        looplist = re.split(r'Interface lo[0-9]+', raw_result)
        looplist.remove(looplist[0])
    else:
        looplist = None
    if looplist:
        for loopback in looplist:
            loopback_id = loopback_list.pop(0)
            result[loopback_id] = {}
            loopback = loopback.replace("\n", "")
            admin_state = re.match(r".*Admin state is ([a-z]+).*", loopback)
            if admin_state:
                result[loopback_id]['AdminState'] = admin_state.group(1)
            else:
                result[loopback_id]['AdminState'] = None
            loopback_ipv4ip = re.match(
                r'.*IPv4 address\s+(\d+.\d+.\d+.\d+\/\d+).*',
                loopback)
            if loopback_ipv4ip:
                loopback_ipv4_ip = loopback_ipv4ip.group(1)
                result[loopback_id]['ipv4_address'] = loopback_ipv4_ip
            else:
                result[loopback_id]['ipv4_address'] = None
            loopback_ipv6add = re.match(r'.*IPv6 address\s+(.*)', loopback)
            if loopback_ipv6add:
                loopback_ipv6 = loopback_ipv6add.group(1)
                loopback_ipv6 = loopback_ipv6.strip()
                result[loopback_id]['ipv6_address'] = loopback_ipv6
            else:
                result[loopback_id]['ipv6_address'] = None
    return result


def parse_show_interface_loopback_brief(raw_result):
    """
    Parse the 'show interface loopback brief' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface loopback brief \
        command in a list of dictionaries of the form:
     ::

      [
       {
         'loopback_int': 'lo2',
         'loopback_ip' : '192.168.2.1/24',
         'status': 'up'
       },
       {
         'loopback_int': 'lo1024',
         'loopback_ip' : '192.168.1.1/24',
         'status': 'up'
       }
      ]

    """
    result = {}
    loopback_re = (
        r'(?P<loopback_int>[a-z0-9]+)\s+(?P<loopback_ip>[0-9.\/]+)\s+'
        r'(?P<status>up)'
    )
    result = []
    for line in raw_result.splitlines():
        line = line.strip()
        re_result = re.search(loopback_re, line)
        if re_result:
            loopback_match = re_result.groupdict()
            for key, value in loopback_match.items():
                if value and value.isdigit():
                    loopback_match[key] = int(value)
            result.append(loopback_match)
    return result


def parse_show_vlan(raw_result):
    """
    Parse the 'show vlan' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show vlan command in a \
        dictionary of the form. Returns None if no vlan found or \
        empty dictionary:

     ::

        {
            '1': { 'name': 'vlan1',
                   'ports': [''],
                   'reason': 'admin_down',
                   'reserved': None,
                   'status': 'down',
                   'vlan_id': '1'
             },
             '2': {
                    'name': 'vlan2',
                    'ports': ['7', '3', '8', 'vlan2', '1'],
                    'reason': 'ok',
                    'reserved': None,
                    'status': 'up',
                    'vlan_id': '2'
            }
        }
    """

    vlan_re = (
        r'(?P<vlan_id>\d+)\s+(?P<name>\S+)\s+(?P<status>\S+)\s+'
        r'(?P<reason>\S+)\s*(?P<reserved>\(\w+\))?\s*(?P<ports>[\w ,]*)'
    )

    no_vlan_re = (r'\s*VLAN\s+\d+\s+has\s+not\s+been\s+configured\s*')

    result = {}

    if re.match(no_vlan_re, raw_result, re.IGNORECASE):
        return None
    else:
        for line in raw_result.splitlines():
            re_result = re.search(vlan_re, line)
            if re_result:
                partial = re_result.groupdict()
                partial['ports'] = partial['ports'].split(', ')
                result[partial['vlan_id']] = partial

        if result == {}:
            return None
        else:
            return result


def parse_show_lacp_interface(raw_result):
    """
    Parse the 'show lacp interface' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show lacp interface command in a \
        dictionary of the form:

     ::

        {
                'lag_id': '100',
                'local_port_id': '17'
                'remote_port_id': '0'
                'local_port_priority': '1'
                'remote_port_priority': '0'
                'local_key': '100'
                'remote_key': '0'
                'local_state': {
                    'active': True,
                    'short_time': False,
                    'collecting': False,
                    'state_expired': False,
                    'passive': False,
                    'long_timeout': True,
                    'distributing': False,
                    'aggregable': True,
                    'in_sync': False,
                    'neighbor_state': True,
                    'individual': False,
                    'out_sync': True
                },
                'remote_state': {
                    'active': False,
                    'short_time': False,
                    'collecting': False,
                    'state_expired': False,
                    'passive': True,
                    'long_timeout': True,
                    'distributing': False,
                    'aggregable': True,
                    'in_sync': False,
                    'neighbor_state': False,
                    'individual': False,
                    'out_sync': True
                },
                'local_system_id': '70:72:cf:52:54:84',
                'remote_system_id': '00:00:00:00:00:00',
                'local_system_priority': '65534',
                'remote_system_priority': '0'
            }
    """

    lacp_re = (
        r'Aggregate-name\s*:\s*[lag]*(?P<lag_id>\w*)?[\s \S]*'
        r'Port-id\s*\|\s*(?P<local_port_id>\d*)?\s*\|'
        r'\s*(?P<remote_port_id>\d*)?\s+'
        r'Port-priority\s*\|\s*(?P<local_port_priority>\d*)?\s*\|'
        r'\s*(?P<remote_port_priority>\d*)?\s+'
        r'Key\s*\|\s*(?P<local_key>\d*)?\s*\|'
        r'\s*(?P<remote_key>\d*)?\s+'
        r'State\s*\|\s*(?P<local_state>[APFISLNOCDXE]*)?\s*\|'
        r'\s*(?P<remote_state>[APFISLNOCDXE]*)?\s+'
        r'System-id\s*\|\s*'
        r'(?P<local_system_id>([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})?\s*\|'
        r'\s*(?P<remote_system_id>([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})?\s+'
        r'System-priority\s*\|\s*(?P<local_system_priority>\d*)?\s*\|'
        r'\s*(?P<remote_system_priority>\d*)?\s*'
    )

    re_result = re.search(lacp_re, raw_result)
    assert re_result

    result = re_result.groupdict()

    if result['local_system_id'] is None:
        result['local_system_id'] = ''
    if result['remote_system_id'] is None:
        result['remote_system_id'] = ''

    for state in ['local_state', 'remote_state']:
        tmp_dict = {
            'active': 'A' in result[state],
            'short_time': 'S' in result[state],
            'collecting': 'C' in result[state],
            'state_expired': 'X' in result[state],
            'passive': 'P' in result[state],
            'long_timeout': 'L' in result[state],
            'distributing': 'D' in result[state],
            'aggregable': 'F' in result[state],
            'in_sync': 'N' in result[state],
            'neighbor_state': 'E' in result[state],
            'individual': 'I' in result[state],
            'out_sync': 'O' in result[state]
        }

        result[state] = tmp_dict

    return result


def parse_show_lacp_aggregates(raw_result):
    """
    Parse the 'show lacp aggregates' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show lacp interface command in a \
        dictionary of the form:

     ::

            {
                'lag1': {
                    'name': 'lag1',
                    'interfaces': [4, 9],
                    'heartbeat_rate': 'slow',
                    'fallback': False,
                    'hash': 'l3-src-dst',
                    'mode': 'off'
                },
                'lag2': {
                    'name': 'lag2',
                    'interfaces': [],
                    'heartbeat_rate': 'slow',
                    'fallback': False,
                    'hash': 'l3-src-dst',
                    'mode': 'off'
                }
            }
    """

    lacp_re = (
        r'Aggregate-name[ ]+: (?P<name>\w+)\s*'
        r'Aggregated-interfaces\s+:[ ]?(?P<interfaces>[\w \-]*)\s*'
        r'Heartbeat rate[ ]+: (?P<heartbeat_rate>slow|fast)\s*'
        r'Fallback[ ]+: (?P<fallback>true|false)\s*'
        r'Hash[ ]+: (?P<hash>l2-src-dst|l3-src-dst|l4-src-dst)\s*'
        r'Aggregate mode[ ]+: (?P<mode>off|passive|active)\s*'
    )

    result = {}
    for re_result in re.finditer(lacp_re, raw_result):
        lag = re_result.groupdict()
        lag['interfaces'] = lag['interfaces'].split()
        lag['fallback'] = lag['fallback'] == 'true'
        result[lag['name']] = lag

    assert result is not None

    return result


def parse_show_lacp_configuration(raw_result):
    """
    Parse the 'show lacp configuration' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show lacp configuration command in a \
        dictionary of the form:

     ::

            {
                'id': '70:72:cf:af:66:e7',
                'priority': 65534
            }
    """

    configuration_re = (
        r'\s*System-id\s*:\s*(?P<id>\S+)\s*'
        r'System-priority\s*:\s*(?P<priority>\d+)\s*'
    )

    re_result = re.match(configuration_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    result['priority'] = int(result['priority'])
    return result


def parse_show_sflow_interface(raw_result):
    """
    Parse the 'show sflow interface' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show sflow interface command in a \
        dictionary of the form:

     ::

        {
            'interface': '1'
            'sflow': 'enabled',
            'sampling_rate': '20',
            'number_of_samples': '10'
        }
    """

    sflow_info_re = (
        r'sFlow Configuration - Interface\s(?P<interface>\d+)\s*'
        r'-----------------------------------------\s*'
        r'sFlow\s*(?P<sflow>\S+)\s*'
        r'Sampling\sRate\s*(?P<sampling_rate>\d+)\s*'
        r'Number\sof\sSamples\s*(?P<number_of_samples>\d+)\s*'
    )

    re_result = re.search(sflow_info_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value and value.isdigit():
            result[key] = int(value)
    return result


def parse_show_lldp_neighbor_info(raw_result):
    """
    Parse the 'show lldp neighbor-info' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show lldp neighbor-info command in a \
        dictionary of the form:

     ::

            {
                'port': 1,
                'neighbor_entries': 0,
                'neighbor_entries_deleted': 0,
                'neighbor_entries_dropped': 0,
                'neighbor_entries_age_out': 0,
                'neighbor_chassis_name': None,
                'neighbor_chassis_description': None,
                'neighbor_chassis_id': None,
                'neighbor_mgmt_address': None,
                'chassis_capabilities_available': None,
                'chassis_capabilities_enabled': None,
                'neighbor_port_id': None,
                'ttl': None
            }
    """

    neighbor_info_re = (
        r'\s*Port\s+:\s*(?P<port>\d+)\n'
        r'Neighbor entries\s+:\s*(?P<neighbor_entries>\d+)\n'
        r'Neighbor entries deleted\s+:\s*(?P<neighbor_entries_deleted>\d+)\n'
        r'Neighbor entries dropped\s+:\s*(?P<neighbor_entries_dropped>\d+)\n'
        r'Neighbor entries age-out\s+:\s*(?P<neighbor_entries_age_out>\d+)\n'
        r'Neighbor Chassis-Name\s+:\s*(?P<neighbor_chassis_name>\S+)?\n'
        r'Neighbor Chassis-Description\s+:\s*'
        r'(?P<neighbor_chassis_description>[\w\s\n/,#~:.*()_-]+)?'
        r'Neighbor Chassis-ID\s+:\s*(?P<neighbor_chassis_id>[0-9a-f:]+)?\n'
        r'Neighbor Management-Address\s+:\s*'
        r'(?P<neighbor_mgmt_address>[\w:.]+)?\n'
        r'Chassis Capabilities Available\s+:\s*'
        r'(?P<chassis_capabilities_available>[\w\s\n,.*_-]+)?\n'
        r'Chassis Capabilities Enabled\s+:\s*'
        r'(?P<chassis_capabilities_enabled>[\w\s\n,.*_-]+)?\n'
        r'Neighbor Port-ID\s+:\s*(?P<neighbor_port_id>[\w\s\n/,.*_-]+)?\n'
        r'TTL\s+:\s*(?P<ttl>\d+)?'
    )

    re_result = re.search(neighbor_info_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value and value.isdigit():
            result[key] = int(value)
    return result


def parse_show_lldp_statistics(raw_result):
    """
    Parse the 'show lldp statistics' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show lldp statistics command in a \
        dictionary of the form:

     ::

            {
                'total_packets_transmited': 0,
                'total_packets_received': 0,
                'total_packets_received_and_discarded': 0,
                'total_tlvs_unrecognized': 0
            }
    """

    neighbor_info_re = (
        r'\s*Total\sPackets\stransmitted\s*:\s*'
        r'(?P<total_packets_transmited>\d+)\s*'
        r'Total\sPackets\sreceived\s*:\s*(?P<total_packets_received>\d+)\s*'
        r'Total\sPacket\sreceived\sand\sdiscarded\s*:\s*'
        r'(?P<total_packets_received_and_discarded>\d+)\s*'
        r'Total\sTLVs\sunrecognized\s*:\s*(?P<total_tlvs_unrecognized>\d+)\s*'

    )

    re_result = re.search(neighbor_info_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value and value.isdigit():
            result[key] = int(value)

    return result


def parse_show_sftp_server(raw_result):
    """
    Parse the 'show sftp server' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show sftp command in a \
        list of dictionaries of the form:
     ::

        {
             'status' : 'Enabled',
             'ServerName' : 'SFTP server'
        }
     """
    sftp_status_re = (
        r'((?P<ServerName>\w+\s+\w+)\s+:\s+(?P<status>\w+))'
    )
    result = {}
    re_result = re.search(sftp_status_re, raw_result)
    assert re_result
    if re_result:
        for key, value in re_result.groupdict().items():
            if value is None:
                result[key] = "No Match found"
            else:
                result[key] = value
    return result


def parse_show_ip_bgp_summary(raw_result):
    """
    Parse the 'show ip bgp summary' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip bgp summary command in a \
        dictionary of the form:

     ::

        {
            'bgp_router_identifier': '1.0.0.1',
            'local_as_number': 64000,
            'rib_entries': 15,
            'peers': 2,
            '20.1.1.1': { 'AS': 65000,
                   'msgrcvd': 83,
                   'msgsent': 86,
                   'up_down': '01:19:21',
                   'state': 'Established',
                   'neighbor': '20.1.1.1'
             },
            '20.1.1.2': { 'AS': 65000,
                   'msgrcvd': 100,
                   'msgsent': 105,
                   'up_down': '01:22:22',
                   'state': 'Established',
                   'neighbor': '20.1.1.2'
            }
        }
    """

    local_bgp_re = (
        r'BGP router identifier (?P<bgp_router_identifier>[^,]+), '
        r'local AS number (?P<local_as_number>\d+)\nRIB entries '
        r'(?P<rib_entries>\d+)\nPeers (?P<peers>\d+)\n\n'
    )

    summary_re = (
        r'(?P<neighbor>\S+)\s+(?P<as_number>\d+)\s+(?P<msgrcvd>\d+)\s+'
        r'(?P<msgsent>\d+)\s+(?P<up_down>\S+)\s+(?P<state>\w+)\s*'
    )

    result = {}
    re_result = re.match(local_bgp_re, raw_result)
    assert re_result
    result = re_result.groupdict()
    for key, value in result.items():
        if value and value.isdigit():
            result[key] = int(value)

    for line in raw_result.splitlines():
        re_result = re.search(summary_re, line)
        if re_result:
            partial = re_result.groupdict()
            for key, value in partial.items():
                if value and value.isdigit():
                    partial[key] = int(value)
            result[partial['neighbor']] = partial

    return result


def parse_show_ip_bgp_neighbors(raw_result):
    """
    Parse the 'show ip bgp neighbor' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip bgp neighbor command in a \
        dictionary of the form:

     ::

        {
            '20.1.1.1': { 'name': '20.1.1.1',
                   'remote_as': 65000,
                   'state': 'Established',
                   'tcp_port_number': 179 ,
                   'bgp_peer_dropped_count': 0,
                   'bgp_peer_dynamic_cap_in_count': 0,
                   'bgp_peer_dynamic_cap_out_count': 0,
                   'bgp_peer_established_count': 1,
                   'bgp_peer_keepalive_in_count': 2,
                   'bgp_peer_keepalive_out_count': 3,
                   'bgp_peer_notify_in_count': 0,
                   'bgp_peer_notify_out_count': 0,
                   'bgp_peer_open_in_count': 0,
                   'bgp_peer_open_out_coun': 1,
                   'bgp_peer_readtime': 249,
                   'bgp_peer_refresh_in_count': 0,
                   'bgp_peer_refresh_out_count': 0,
                   'bgp_peer_resettime': 127,
                   'bgp_peer_update_in_count': 2,
                   'bgp_peer_update_out_count': 2,
                   'bgp_peer_uptime': 189

             },
            '20.1.1.10': { 'name': '20.1.1.10',
                   'remote_as': 65000,
                   'state': 'Established',
                   'tcp_port_number': 179 ,
                   'bgp_peer_dropped_count': 0,
                   'bgp_peer_dynamic_cap_in_count': 0,
                   'bgp_peer_dynamic_cap_out_count': 0,
                   'bgp_peer_established_count': 1,
                   'bgp_peer_keepalive_in_count': 2,
                   'bgp_peer_keepalive_out_count': 3,
                   'bgp_peer_notify_in_count': 0,
                   'bgp_peer_notify_out_count': 0,
                   'bgp_peer_open_in_count': 0,
                   'bgp_peer_open_out_coun': 1,
                   'bgp_peer_readtime': 281,
                   'bgp_peer_refresh_in_count': 0,
                   'bgp_peer_refresh_out_count': 0,
                   'bgp_peer_resettime': 127,
                   'bgp_peer_update_in_count': 2,
                   'bgp_peer_update_out_count': 4,
                   'bgp_peer_uptime': 221

             }
        }
    """

    neighbor_re = (
        r'\s*name: (?P<name>[^,]+), remote-as: (?P<remote_as>\d+)\s+state: '
        r'(?P<state>\w+)\s*tcp_port_number: (?P<tcp_port_number>\d+)'
        r'\s*statistics:\s*bgp_peer_dropped_count: '
        r'(?P<bgp_peer_dropped_count>\d+)\s*bgp_peer_dynamic_cap_in_count: '
        r'(?P<bgp_peer_dynamic_cap_in_count>\d+)'
        r'\s*bgp_peer_dynamic_cap_out_count: '
        r'(?P<bgp_peer_dynamic_cap_out_count>\d+)'
        r'\s*bgp_peer_established_count: (?P<bgp_peer_established_count>\d+)'
        r'\s*bgp_peer_keepalive_in_count: '
        r'(?P<bgp_peer_keepalive_in_count>\d+)'
        r'\s*bgp_peer_keepalive_out_count: '
        r'(?P<bgp_peer_keepalive_out_count>\d+)\s*bgp_peer_notify_in_count: '
        r'(?P<bgp_peer_notify_in_count>\d+)\s*bgp_peer_notify_out_count: '
        r'(?P<bgp_peer_notify_out_count>\d+)\s*bgp_peer_open_in_count: '
        r'(?P<bgp_peer_open_in_count>\d+)\s*bgp_peer_open_out_count: '
        r'(?P<bgp_peer_open_out_count>\d+)\s*bgp_peer_readtime: '
        r'(?P<bgp_peer_readtime>\d+)\s*bgp_peer_refresh_in_count: '
        r'(?P<bgp_peer_refresh_in_count>\d+)\s*bgp_peer_refresh_out_count: '
        r'(?P<bgp_peer_refresh_out_count>\d+)\s*bgp_peer_resettime: '
        r'(?P<bgp_peer_resettime>\d+)\s*bgp_peer_update_in_count: '
        r'(?P<bgp_peer_update_in_count>\d+)\s*bgp_peer_update_out_count: '
        r'(?P<bgp_peer_update_out_count>\d+)\s*bgp_peer_uptime: '
        r'(?P<bgp_peer_uptime>\d+)\s*'
    )

    result = {}
    for re_result in re.finditer(neighbor_re, raw_result):
        partial = re_result.groupdict()
        for key, value in partial.items():
            if value and value.isdigit():
                partial[key] = int(value)
        result[partial['name']] = partial

    return result


def parse_show_ip_bgp(raw_result):
    """
    Parse the 'show ip bgp' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip bgp command in a \
        list of dictionaries of the form:

     ::

        [
            {
                'route_status': '*>',
                'network': '10.2.0.2/32',
                'next_hop': '20.1.1.1',
                'metric': 0,
                'locprf': 0,
                'weight': 0,
                'path': '65000 64100 i'
            },
            {
                'route_status': '*',
                'network': '10.2.0.2/32',
                'next_hop': '20.1.1.10',
                'metric': 0,
                'locprf': 0,
                'weight': 0,
                'path': '65000 64100 i'
            }
        ]
    """

    routes_re = (
        r'(?P<route_status>[*>sdh=iSR]+)\s+(?P<network>\S+)\s+'
        r'(?P<next_hop>\S+)\s+(?P<metric>\d+)\s+(?P<locprf>\d+)\s+'
        r'(?P<weight>\d+)\s+(?P<path>.*)\w?\s*'
    )

    result = []
    for line in raw_result.splitlines():
        re_result = re.search(routes_re, line)
        if re_result:
            partial = re_result.groupdict()
            for key, value in partial.items():
                if value and value.isdigit():
                    partial[key] = int(value)
            result.append(partial)

    return result


def parse_show_ipv6_bgp(raw_result):
    """
    Parse the 'show ipv6 bgp' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ipv6 bgp command in a \
        list of dictionaries of the form:

     ::

        [
            {
                'route_status': '*>',
                'network': '10::/126',
                'next_hop': '::',
                'metric': 0,
                'locprf': 0,
                'weight': 0,
                'path': '65000 64100 i'
            },
            {
                'route_status': '*',
                'network': '10::/126',
                'next_hop': '3::1',
                'metric': 0,
                'locprf': 0,
                'weight': 0,
                'path': '65000 64100 i'
            }
        ]
    """

    routes_re = (
        r'(?P<route_status>[*>sdh=iSR]+)\s+(?P<network>\S+)\s+'
        r'(?P<next_hop>\S+)\s+(?P<metric>\d+)\s+(?P<locprf>\d+)\s+'
        r'(?P<weight>\d+)\s+(?P<path>.*)\w?\s*'
    )

    result = []
    for line in raw_result.splitlines():
        re_result = re.search(routes_re, line)
        if re_result:
            partial = re_result.groupdict()
            for key, value in partial.items():
                if value and value.isdigit():
                    partial[key] = int(value)
            result.append(partial)

    return result


def parse_show_ip_ospf_neighbor_detail(raw_result):
    """
    Parse the 'show ip ospf neighbor detail' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip ospf neighbor detail command \
        in a dictionary of the form:

     ::

        {
            '2.2.2.2': {'Neighbor': '2.2.2.2',
                'dead_timer': '30.763s',
                'area': '0.0.0.0',
                'time': '9.240s',
                'state_change': 1,
                'interface_address': '10.10.10.2',
                'priority': 1,
                'link_req_list': 0,
                'state': 'Init',
                'admin_state': 'up',
                'db_summary_list': 0,
                'BDR': '0.0.0.0',
                'interface': 1,
                'link_retrans_list': 0,
                'DR': '0.0.0.0',
                'options': 0

            }
        }
    """

    neighbor_re = (
        r'\s*Neighbor (?P<Neighbor>[^,]+),\s*interface address '
        '(?P<interface_address>[0-255.]+).*'
        r'\s*[\w ]+area (?P<area>[0-255.]+) via interface '
        '(?P<interface>\d+).*'
        r'\s*[\w ]+priority is (?P<priority>\d+), State is '
        '(?P<state>\S+), (?P<state_change>\d+)[\w ]+.*'
        r'\s*Neighbor is (?P<admin_state>\w+) for '
        '(?P<hello_timer>[\d.]+s).*'
        r'\s*DR is (?P<DR>[0-255.]+),BDR is '
        '(?P<BDR>[0-255.]+).*'
        r'\s*Options (?P<options>\d+).*'
        r'\s*Dead timer due in (?P<dead_timer>[\d.]+s).*'
        r'\s*Database Summary List (?P<db_summary_list>\d+).*'
        r'\s*Link State Request List (?P<link_req_list>\d+).*'
        r'\s*Link State Retransmission List '
        '(?P<link_retrans_list>\d+)'
    )

    result = {}
    for re_result in re.finditer(neighbor_re, raw_result):
        partial = re_result.groupdict()
        for key, value in partial.items():
            if value and value.isdigit():
                partial[key] = int(value)
        result[partial['Neighbor']] = partial
    return result


def parse_show_ip_ospf_neighbor(raw_result):
    """
    Parse the 'show ip ospf neighbor' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip ospf neighbor command in a \
        dictionary of the form:

     ::

        {
            'neighbor_id': '2.2.2.2',
            'priority': '1',
            'state': 'Full/Backup',
            'dead_time': '31.396s',
            'address': '10.0.1.1',
            'interface': '1:10.0.1.2/24',
            'rxmtl': '0',
            'rqstl': '0',
            'dbsml': '0'
        }
    """

    neighbor_re = (
        r'(?P<neighbor_id>[^ ]+)\s*(?P<priority>[^ ]+)\s*'
        '(?P<state>[^ ]+)'
        r'\s*(?P<dead_time>[^ ]+)\s*(?P<address>[^ ]+)\s*'
        '(?P<interface>[^ ]+)'
        r'\s*(?P<rxmtl>[^ ]+)\s*(?P<rqstl>[^ ]+)\s*(?P<dbsml>[^ ])'
    )

    result = {}
    pattern_found = False
    for line in raw_result.splitlines():
        if (pattern_found is True):
            re_result = re.search(neighbor_re, line)
            if (re_result):
                partial = re_result.groupdict()
                result[partial['neighbor_id']] = partial
        else:
            re_result = re.search('-+\s*-+', line)
            if (re_result):
                pattern_found = True

    return result


def parse_show_ip_ospf_interface(raw_result):
    """
    Parse the 'show ip ospf interface' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip ospf interface command in a \
        dictionary of the form:

     ::

        {
           'router_id': '2.2.2.2',
           'priority': '1',
           'Area_id': '0.0.0.1',
           'cost': '10',
           'retransmit_time': '5',
           'neighbor_count': '1',
           'wait_time': '40',
           'state': '<DR >',
           'Designated Router (ID)': '2.2.2.2',
           'DR_Interface_address': '10.10.10.1',
           'Backup Designated Router (ID)': '1.1.1.1',
           'BDR_Interface_address': '10.10.10.2',
           'hello_due_time': '7.717s',
           'Adjacent_neigbhor_count': '1',
           'internet_address': '10.10.10.2/24',
           'dead_timer': '40',
           'hello_timer': '10',
           'transmit_delay': '1'
        }
    """

    show_ip_ospf_int_re = (
        r'\s*Interface (?P<Interface_id>\d) BW '
        '(?P<bandwidth>\d+) Mbps.*'
        r'\s*Internet address (?P<internet_address>[0-255.]+\S+) '
        'Area (?P<Area_id>[0-255.]+).*'
        r'\s*Router ID : (?P<router_id>[0-255.]+), Network Type '
        '(?P<network_type>\S+), Cost: (?P<cost>\d+).*'
        r'\s*Transmit Delay is (?P<transmit_delay>\d) sec, State '
        '(?P<state>\S+\s*\S+), Priority (?P<priority>\d)\s*'
        r'[\S ]+\(ID\)\s*'
        '(?P<Designated_router>[0-255.]+),\s*Interface Address '
        '(?P<DR_Interface_address>[0-255.]+).*')

    show_ip_ospf_int_re1 = (
        r'\s*Hello (?P<hello_timer>\d+) Dead (?P<dead_timer>\d+) '
        'wait (?P<wait_time>\d+) Retransmit '
        '(?P<retransmit_time>\d+).*'
        r'\s*Hello due in\s*(?P<hello_due_time>\S+).*'
        r'\Neighbor Count is\s*(?P<neighbor_count>\d),\s*Adjacent '
        'neighbor count is\s*(?P<Adjacent_neigbhor_count>\d)'
    )

    bdr_re = (
        r'\s*Backup Designated Router \(ID\) '
        '(?P<Backup_designated_router>[0-255.]+),\s*Interface '
        'Address (?P<BDR_Interface_address>[0-255.]+).*'
    )

    error_no_record = (
        r'No\s*backup\s*designated\.*')

    result = {}

    re_result = re.search(show_ip_ospf_int_re, raw_result, re.DOTALL)
    if (re_result):
        result = re_result.groupdict()

    re_result = re.search(show_ip_ospf_int_re1, raw_result, re.DOTALL)
    if (re_result):
        result1 = re_result.groupdict()
        result.update(result1)

    re_result = re.search(error_no_record, raw_result, re.DOTALL)
    if (re_result):
        return result

    re_result = re.search(bdr_re, raw_result, re.DOTALL)
    if (re_result):
        result1 = re_result.groupdict()
        result.update(result1)

    return result


def parse_show_ip_ospf(raw_result):
    """
    Parse the 'show ip ospf' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip ospf interface command in a \
        dictionary of the form:

     ::

        {
            'router_id': '2.2.2.2',
            'no_of_area': '1',
            '0.0.0.0':
                {
                    'network_checksum': '0x00000000',
                    'no_of_active_interfaces': 1,
                    'area_id': '0.0.0.0',
                    'router_checksum': '0x00008d77',
                    'opaque_link_checksum': '0x00000000',
                    'opaque_link': 0,
                    'opaque_area': 0,
                    'abr_summary_lsa': 0,
                    'no_of_lsa': 2,
                    'asbr_summary_lsa': 0,
                    'no_of_interfaces': 1,
                    'opaque_area_checksum': '0x00000000',
                    'authentication_type': 'no authentication',
                    'nssa_checksum': '0x00000000',
                    'router_lsa': 2,
                    'abr_checksum': '0x00000000',
                    'network_lsa': 0,
                    'asbr_checksum': '0x00000000',
                    'nssa_lsa': 0
                }
        }
    """

    router_re = (
        r'[\S ]+Router\s*ID:\s*(?P<router_id>[\S]+).*'
        r'[\S ]+router:\s*(?P<no_of_area>\d+).*'
    )

    area_re = (
        r':\s*(?P<area_id>[0-255.]+).*'
        r'[\S ]+area:\s*Total:\s*(?P<no_of_interfaces>\d+),\s*Active:'
        '\s*?(?P<no_of_active_interfaces>\d+).*'
        r'[\S ]+Area\s*has\s*(?P<authentication_type>[\S ]+).*'
        r'[\S ]+LSA\s*(?P<no_of_lsa>\d+).*'
        r'[\S ]+router\s*LSA\s*(?P<router_lsa>\d+)[\S ]+Sum\s*'
        '(?P<router_checksum>[\S]+).*'
        r'[\S ]+network\s*LSA\s*(?P<network_lsa>\d+)[\S ]+Sum\s*'
        '(?P<network_checksum>[\S]+).*'
        r'[\S ]+ABR\s*summary\s*LSA\s*(?P<abr_summary_lsa>\d+)'
        '[\S ]+Sum\s*(?P<abr_checksum>[\S]+).*'
        r'[\S ]+ASBR\s*summary\s*LSA\s*(?P<asbr_summary_lsa>\d+)'
        '[\S ]+Sum\s*(?P<asbr_checksum>[\S]+).*'
        r'[\S ]+NSSA\s*LSA\s*(?P<nssa_lsa>\d+)[\S ]+Sum\s*'
        '(?P<nssa_checksum>[\S]+).*'
        r'[\S ]+opaque\s*link\s*(?P<opaque_link>\d+)[\S ]+Sum\s*'
        '(?P<opaque_link_checksum>[\S]+).*'
        r'[\S ]+opaque\s*area\s*(?P<opaque_area>\d+)[\S ]+Sum\s*'
        '(?P<opaque_area_checksum>[\S]+).*'
    )

    result = {}
    result_area = {}
    lines = []
    output = raw_result.split('Area ID')
    if(output):
        no_of_instance = len(output)
        for i in range(0, no_of_instance):
            if i == 0:
                re_result = re.match(router_re, output[i], re.DOTALL)
                if(re_result):
                    result = re_result.groupdict()
            if i <= int(result['no_of_area']):
                re_result = re.match(area_re, output[i], re.DOTALL)
                if(re_result):
                    partial = re_result.groupdict()
                    areas = partial['area_id']
                    lines.append(areas)
                    for key, value in partial.items():
                        if value and value.isdigit():
                            partial[key] = int(value)
                            result_area[partial['area_id']] = partial
                    result.update(result_area)
        return result


def parse_ping_repetitions(raw_result):
    """
    Parse the 'ping' command raw output.

    :param str raw_result: ping raw result string.
    :rtype: dict
    :return: The parsed result of the ping command in a \
        list of dictionaries of the form:

     ::

        {
            'transmitted': 0,
            'received': 0,
            'errors': 0,
            'packet_loss': 0
        }
    """

    ping_re = (
        r'^(?P<transmitted>\d+) packets transmitted, '
        r'(?P<received>\d+) received,'
        r'( \+(?P<errors>\d+) errors,)? '
        r'(?P<packet_loss>\d+)% packet loss, '
    )

    result = {}
    for line in raw_result.splitlines():
        re_result = re.search(ping_re, line)
        if re_result:
            for key, value in re_result.groupdict().items():
                if value is None:
                    result[key] = 0
                elif value.isdigit():
                    result[key] = int(value)

    return result


def parse_ping6_repetitions(raw_result):
    """
    Parse the 'ping6' command raw output.

    :param str raw_result: ping6 raw result string.
    :rtype: dict
    :return: The parsed result of the ping6 command in a \
        list of dictionaries of the form:

     ::

        {
            'transmitted': 0,
            'received': 0,
            'errors': 0,
            'packet_loss': 0
        }
    """

    ping_re = (
        r'^(?P<transmitted>\d+) packets transmitted, '
        r'(?P<received>\d+) received,'
        r'( \+(?P<errors>\d+) errors,)? '
        r'(?P<packet_loss>\d+)% packet loss, '
    )

    result = {}
    for line in raw_result.splitlines():
        re_result = re.search(ping_re, line)
        if re_result:
            for key, value in re_result.groupdict().items():
                if value is None:
                    result[key] = 0
                elif value.isdigit():
                    result[key] = int(value)

    return result


def parse_ping(raw_result):
    """
    Parse the 'ping' command raw output.

    :param str raw_result: ping raw result string.
    :rtype: dict
    :return: The parsed result of the ping command in a \
        dictionary of the form:

     ::

        {
            'transmitted': 0,
            'received': 0,
            'errors': 0,
            'packet_loss': 0
        }
    """

    ping_re1 = (
        r'\s*(?P<transmitted>\d+)\s+packets transmitted,'
        r'\s+(?P<received>\d+)\s+received,'
        r'(\s+\+(?P<errors>\d+)\s+errors,)?'
        r'\s+(?P<loss_pc>\d+)% packet loss,'
        r'\s+time\s+(?P<time>\d+)ms'
    )

    ping_re2 = (
        r'(.*\s+(?P<datagram_size>\d+)\(\d+\))\s+bytes of data.'
    )

    ping_re3 = (
        r'(\s*RR:\s+(?P<record_route>(\d+.\d+.\d+.\d+)))'
    )

    ping_re4 = (
        r'((\s*TS:\s+(?P<time_stamp>\d+))\s+absolute*)'
    )

    ping_re5 = (
        r'(\s*TS:\s+(?P<Route_address>(\d+.\d+.\d+.\d+))'
        r'\s+(?P<timestamp>\d+)\s+absolute*)'
    )
    ping_re6 = (
        r'\s*PATTERN:\s+0x(?P<data>([a-fA-F0-9]+))'
    )

    result = {}
    re_result1 = re.search(ping_re1, raw_result)
    if re_result1:
        for key, value in re_result1.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    re_result2 = re.search(ping_re2, raw_result)
    if re_result2:
        for key, value in re_result2.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    re_result3 = re.search(ping_re3, raw_result)
    if re_result3:
        for key, value in re_result3.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    re_result4 = re.search(ping_re4, raw_result)
    if re_result4:
        for key, value in re_result4.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    re_result5 = re.search(ping_re5, raw_result)
    if re_result5:
        for key, value in re_result5.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    re_result6 = re.search(ping_re6, raw_result)
    if re_result6:
        for key, value in re_result6.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    return result


def parse_ping6(raw_result):
    """
    Parse the 'ping6' command raw output.

    :param str raw_result: ping6 raw result string.
    :rtype: dict
    :return: The parsed result of the ping6 command in a \
        dictionary of the form:

     ::

        {
            'transmitted': 0,
            'received': 0,
            'errors': 0,
            'packet_loss': 0
        }
    """
    ping6_re1 = (
        r'\s*(?P<transmitted>\d+)\s+packets transmitted,'
        r'\s+(?P<received>\d+)\s+received,'
        r'(\s+\+(?P<errors>\d+)\s+errors,)?'
        r'\s+(?P<loss_pc>\d+)% packet loss,'
        r'\s+time\s+(?P<time>\d+)ms'
    )

    ping6_re2 = (
        r'(.*\s+(?P<datagram_size>\d+))\s+data bytes*'
    )
    ping6_re3 = (
        r'\s*PATTERN:\s+0x(?P<data>([a-fA-F0-9]+))'
    )

    result = {}
    re_result1 = re.search(ping6_re1, raw_result)
    if re_result1:
        for key, value in re_result1.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    re_result2 = re.search(ping6_re2, raw_result)
    if re_result2:
        for key, value in re_result2.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    re_result3 = re.search(ping6_re3, raw_result)
    if re_result3:
        for key, value in re_result3.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    return result


def parse_traceroute(raw_result):
    """
    Parse the 'traceroute' command raw output.

    :param str raw_result: traceroute raw result string.
    :rtype: dict
    :return: The parsed result of the traceroute command in a \
        dictionary of the form:

     ::

        {1: {'time_stamp2': '0.189',
             'time_stamp3': '0.141',
             'time_stamp1': '0.217',
             'hop_num': 1,
             'int_hop': '50.1.1.4'
            },
         2: {'time_stamp2': '0.144',
             'time_stamp3': '0.222',
             'time_stamp1': '0.216',
             'hop_num': 2,
             'int_hop': '40.1.1.3'
            },
         'probe': 3,
         'min_ttl': 1,
         'dest_addr': '10.1.1.10',
         'max_ttl': 30,
         'time_out': 3
         }

    """
    traceroute_re1 = (
        r'(.*\s+(?P<dst_unreachable>!H)\s*?.*)'
    )

    traceroute_re2 = (
        r'(\s*(?P<hop_number>\d+)\s+(?P<hop_timeout>(\*\s+)+))'
    )

    traceroute_re3 = (
        r'.*\s*(?P<network_unreachable>(Network is unreachable))\s*'
    )

    traceroute_re4 = (
        r'\s*traceroute to\s+(?P<dest_addr>(\d+.\d+.\d+.\d+))\s+'
    )

    traceroute_re5 = (
        r'.*\s+(?P<min_ttl>\d+)\s+hops min,'
        r'.*\s+(?P<max_ttl>\d+)\s+hops max,'
        r'.*\s+(?P<time_out>\d+)\s+sec. timeout,'
        r'.*\s+(?P<probe>\d+)\s+probes'
    )

    traceroute_re6 = (
        r'(\s*(?P<hop_num>\d+)\s+(?P<int_hop>(\d+.\d+.\d+.\d+))\s+'
        r'(?P<time_stamp1>(\d+.\d+))ms\s+'
        r'((?P<time_stamp2>(\d+.\d+))ms\s+)?'
        r'((?P<time_stamp3>(\d+.\d+))ms\s+)?'
        r'((?P<time_stamp4>(\d+.\d+))ms\s+)?'
        r'((?P<time_stamp5>(\d+.\d+))ms\s*)?.*)'
    )

    result = {}
    re_result1 = re.search(traceroute_re1, raw_result)
    if re_result1:
        for key, value in re_result1.groupdict().items():
            if value is None:
                result[key] = 'No match found'
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
        return result

    re_result2 = re.search(traceroute_re2, raw_result)
    if re_result2:
        for key, value in re_result2.groupdict().items():
            if value is None:
                result[key] = 'No match found'
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
        return result

    re_result3 = re.search(traceroute_re3, raw_result)
    if re_result3:
        for key, value in re_result3.groupdict().items():
            if value is None:
                result[key] = 'No match found'
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
        return result

    raw_result_lines = raw_result.splitlines()
    length = len(raw_result_lines)
    re_result4 = re.search(traceroute_re4, raw_result)
    if re_result4:
        for key, value in re_result4.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    re_result5 = re.search(traceroute_re5, raw_result)
    if re_result5:
        for key, value in re_result5.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
    for hop_num in range(1, length):
        result[hop_num] = {}
        re_result6 = re.search(traceroute_re6, raw_result_lines[hop_num])
        if re_result6:
            for key, value in re_result6.groupdict().items():
                if value is None:
                    result[hop_num][key] = "No match found"
                elif value.isdigit():
                    result[hop_num][key] = int(value)
                else:
                    result[hop_num][key] = value

    return result


def parse_traceroute6(raw_result):
    """
    Parse the 'traceroute6' command raw output.

    :param str raw_result: traceroute6 raw result string.
    :rtype: dict
    :return: The parsed result of the traceroute6 command in a \
        dictionary of the form:

     ::

        {1: {'time_stamp2': '0.189',
             'time_stamp3': '0.141',
             'time_stamp1': '0.217',
             'hop_num': 1,
             'int_hop': '(5001::4)'
            },
         2: {'time_stamp2': '0.144',
             'time_stamp3': '0.222',
             'time_stamp1': '0.216',
             'hop_num': 2,
             'int_hop': '(4001::3)'
            },
         'probe': 3,
         'min_ttl': 1,
         'dest_addr': '1001::10',
         'source_addr': '5001::4',
         'max_ttl': 30,
         'time_out': 3
         }

    """
    traceroute6_re1 = (
        r'(.*\s+(?P<dst_unreachable>!H)\s*?.*)'
    )

    traceroute6_re2 = (
        r'(\s*(?P<hop_number>\d+)\s+(?P<hop_timeout>(\*\s+)+))'
    )

    traceroute6_re3 = (
        r'.*\s*(?P<network_unreachable>(Network is unreachable))\s*'
    )

    traceroute6_re4 = (
        r'\s*traceroute to\s+(?P<dest_addr>\S+)\s+'
        r'.*\s+from (?P<source_addr>\S+),\s+'
    )

    traceroute6_re5 = (
        r'.*\s+(?P<max_ttl>\d+)\s+hops max,'
        r'.*\s+(?P<time_out>\d+)\s+sec. timeout,'
        r'.*\s+(?P<probe>\d+)\s+probes'
    )

    traceroute6_re6 = (
        r'(\s*(?P<hop_num>\d+)\s+(?P<int_hop>\S+)\s+(\S+)\s+'
        r'(?P<time_stamp1>(\d+.\d+)) ms\s+'
        r'((?P<time_stamp2>(\d+.\d+)) ms\s+)?'
        r'((?P<time_stamp3>(\d+.\d+)) ms\s+)?'
        r'((?P<time_stamp4>(\d+.\d+)) ms\s+)?'
        r'((?P<time_stamp5>(\d+.\d+)) ms\s*)?.*)'
    )

    result = {}
    re_result1 = re.search(traceroute6_re1, raw_result)
    if re_result1:
        for key, value in re_result1.groupdict().items():
            if value is None:
                result[key] = 'No match found'
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
        return result

    re_result2 = re.search(traceroute6_re2, raw_result)
    if re_result2:
        for key, value in re_result2.groupdict().items():
            if value is None:
                result[key] = 'No match found'
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
        return result

    re_result3 = re.search(traceroute6_re3, raw_result)
    if re_result3:
        for key, value in re_result3.groupdict().items():
            if value is None:
                result[key] = 'No match found'
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value
        return result

    raw_result_lines = raw_result.splitlines()
    length = len(raw_result_lines)
    re_result4 = re.search(traceroute6_re4, raw_result)
    if re_result4:
        for key, value in re_result4.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    re_result5 = re.search(traceroute6_re5, raw_result)
    if re_result5:
        for key, value in re_result5.groupdict().items():
            if value is None:
                result[key] = "No match found"
            elif value.isdigit():
                result[key] = int(value)
            else:
                result[key] = value

    for hop_num in range(1, length):
        result[hop_num] = {}
        re_result6 = re.search(traceroute6_re6, raw_result_lines[hop_num])
        if re_result6:
            for key, value in re_result6.groupdict().items():
                if value is None:
                    result[hop_num][key] = "No match found"
                elif value.isdigit():
                    result[hop_num][key] = int(value)
                else:
                    result[hop_num][key] = value

    return result


def parse_show_rib(raw_result):
    """
    Parse the 'show rib' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show rib command in a \
        dictionary of the form:

     ::

        {
            'ipv4_entries': [
                {
                    'id': '140.0.0.0',
                    'prefix': '30',
                    'selected': True,
                    'next_hops': [
                        {
                            'selected': True,
                            'via': '10.10.0.2',
                            'distance': '20',
                            'from': 'BGP',
                            'metric': '0'
                        }
                    ]
                },
                {
                    'id': '193.0.0.2',
                    'prefix': '32',
                    'selected': True,
                    'next_hops': [
                        {
                            'selected': True,
                            'via': '50.0.0.2',
                            'distance': '1',
                            'from': 'static',
                            'metric': '0'
                        },
                        {
                            'selected': True,
                            'via': '56.0.0.3',
                            'distance': '1',
                            'from': 'static',
                            'metric': '0'
                        }
                    ]
                },
                {
                    'id': '10.10.0.0',
                    'prefix': '24',
                    'selected': True,
                    'next_hops': [
                        {
                            'selected': True,
                            'via': '1',
                            'distance': '0',
                            'from': 'connected',
                            'metric': '0'
                        }
                    ]
                }
            ],
            'ipv6_entries': [
                {
                    'id': '2002::/64',
                    'selected': True,
                    'next_hops': [
                        {
                            'selected': True,
                            'via': '4',
                            'distance': '0',
                            'from': 'connected',
                            'metric': '0'
                        }
                    ]
                },
                {
                    'id': '2010:bd9::/32',
                    'selected': True,
                    'next_hops': [
                        {
                            'selected': True,
                            'via': '2005::2',
                            'distance': '1',
                            'from': 'static',
                            'metric': '0'
                        },
                        {
                            'selected': True,
                            'via': '2001::2',
                            'distance': '1',
                            'from': 'static',
                            'metric': '0'
                        },
                        {
                            'selected': False,
                            'via': '2002::2',
                            'distance': '1',
                            'from': 'static',
                            'metric': '0'
                        }
                    ]
                }
            ]
        }
    """

    ipv4_entries_re = (
        r'(?<!No )ipv4 rib entries'
    )

    ipv6_entries_re = (
        r'(?<!No )ipv6 rib entries'
    )

    ipv4_network_re = (
        r'(?P<selected>\*?)(?P<network>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)'
    )

    ipv6_network_re = (
        r'(?P<selected>\*?)'
        r'(?P<network>(?:(?:(?:[0-9A-Za-z]+:)+:?([0-9A-Za-z]+)?)+)/\d+)'
    )

    ipv4_nexthop_re = (
        r'(?P<selected>\*?)via\s+(?P<via>(?:\d+\.\d+\.\d+\.\d+|\d+)),\s+'
        r'\[(?P<distance>\d+)/(?P<metric>\d+)\],\s+(?P<from>\S+)'
    )

    ipv6_nexthop_re = (
        r'(?P<selected>\*?)'
        r'via\s+(?P<via>(?:(?:(?:[0-9A-Za-z]+:)+:?([0-9A-Za-z]+)?)+|\d+)),\s+'
        r'\[(?P<distance>\d+)/(?P<metric>\d+)\],\s+(?P<from>\S+)'
    )

    result = {}
    result['ipv4_entries'] = []
    result['ipv6_entries'] = []

    lines = raw_result.splitlines()
    line_index = 0

    while line_index < len(lines):
        if re.search(ipv4_entries_re, lines[line_index]):

            check_for_ipv4_entries = False

            while (not check_for_ipv4_entries and line_index < len(lines)):
                if re.search(ipv4_network_re, lines[line_index]):
                    check_for_ipv4_entries = True
                else:
                    line_index += 1

            while (check_for_ipv4_entries and line_index < len(lines)):
                re_result = re.search(ipv4_network_re, lines[line_index])

                if re_result:
                    network = {}
                    partial = re_result.groupdict()

                    if partial['selected'] == '*':
                        network['selected'] = True
                    else:
                        network['selected'] = False

                    network['id'] = partial['network']
                    network['prefix'] = partial['prefix']

                    network['next_hops'] = []
                    check_for_next_hops = True

                    line_index += 1

                    while (check_for_next_hops and line_index < len(lines)):
                        re_result = re.search(
                            ipv4_nexthop_re,
                            lines[line_index]
                        )

                        if re_result:
                            partial = re_result.groupdict()

                            if partial['selected'] == '*':
                                partial['selected'] = True
                            else:
                                partial['selected'] = False

                            network['next_hops'].append(partial)
                            line_index += 1
                        else:
                            check_for_next_hops = False

                    result['ipv4_entries'].append(network)
                else:
                    check_for_ipv4_entries = False

        if re.search(ipv6_entries_re, lines[line_index]):
            check_for_ipv6_entries = False

            while (not check_for_ipv6_entries and line_index < len(lines)):
                if re.search(ipv6_network_re, lines[line_index]):
                    check_for_ipv6_entries = True
                else:
                    line_index += 1

            while (check_for_ipv6_entries and line_index < len(lines)):
                re_result = re.search(ipv6_network_re, lines[line_index])

                if re_result:
                    network = {}
                    partial = re_result.groupdict()

                    if partial['selected'] == '*':
                        network['selected'] = True
                    else:
                        network['selected'] = False

                    network['id'] = partial['network']

                    network['next_hops'] = []
                    check_for_next_hops = True

                    line_index += 1

                    while (check_for_next_hops and line_index < len(lines)):
                        re_result = re.search(
                            ipv6_nexthop_re,
                            lines[line_index]
                        )

                        if re_result:
                            partial = re_result.groupdict()

                            if partial['selected'] == '*':
                                partial['selected'] = True
                            else:
                                partial['selected'] = False

                            network['next_hops'].append(partial)
                            line_index += 1
                        else:
                            check_for_next_hops = False

                    result['ipv6_entries'].append(network)
                else:
                    check_for_ipv6_entries = False

        line_index += 1

    return result


def parse_show_running_config(raw_result):
    """
    Parse the 'show running-config' command raw output.
    This parser currently returns only BGP, OSPF, vlan and interface section
    of the show-running command, please review the doc/developer.rst file to
    get more information on adding new sections.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show vlan command in a
              dictionary of the form:

     ::

        {
        'interface': {
            '50': {
                'admin': 'up',
                'routing': 'no',
                'vlan': [
                    {'mode': 'trunk', 'type': 'allowed', 'vlanid': '10'},
                    {'mode': 'trunk', 'type': 'allowed', 'vlanid': '11'},
                    {'mode': 'trunk', 'type': 'allowed', 'vlanid': '12'}
                    ],
                'autonegotiation': 'off',
                'flowcontrol': {'receive': 'on', 'send': 'on'},
                'mtu': '1518'
                },
            'vlan10': {
                'admin': 'up',
                'ipv4': '10.1.10.1/24'
                },
            '2': {
                'admin': 'up',
                'routing': 'no',
                'vlan': [{'mode': 'access', 'vlanid': '8'}]
                },
            'mgmt': {'static': '1.1.1.1/24', 'nameserver': '2.2.2.2'},
            'vlan11': {
                'admin': 'up',
                'ipv4': '10.1.11.1/24'
                },
            'vlan12': {
                'admin': 'up',
                'ipv4': '10.1.12.1/24'
                },
            '35': {
                'admin': 'up',
                'routing': 'no',
                'lacp': {'priority': '3', 'port-id': '2'},
                'vlan': [
                    {'mode': 'trunk', 'type': 'native', 'vlanid': '8'},
                    {'mode': 'trunk', 'type': 'allowed', 'vlanid': '12'}
                    ],
                'autonegotiation': 'off',
                'speed': '1000',
                'flowcontrol': {'receive': 'on', 'send': 'on'},
                'mtu': '1518'
                },
            '1': {
                'admin': 'up',
                'routing': 'no',
                'vlan': [{'mode': 'access', 'vlanid': '8'}]
                },
            '7': {'admin': 'up', 'ipv4': '100.1.1.100/24'},
            'loopback 2': {
                'ipv4': '10.1.12.1/24',
                'ipv6': '2001::2/64'
                }
        },
        'ospf': {
            'router-id': '7.7.7.7',
            'networks': [
                {'network': '10.1.11.100/24', 'area': '10.1.0.0'},
                {'network': '10.1.12.100/24', 'area': '10.1.0.0'}
            ]
        },
        'vlan': {
            '8': {'admin': 'up', 'vlanid': '8'},
            '10': {'admin': 'up', 'vlanid': '10'},
            '12': {'admin': 'up', 'vlanid': '12'},
            '1': {'admin': 'up', 'vlanid': '1'},
            '11': {'admin': 'up', 'vlanid': '11'}
        },
        'bgp': {
            '6400': {
                'router_id': '7.7.7.7',
                'neighbors': [
                    {'remote-as': '11', 'ip': '10.1.11.100'},
                    {'remote-as': '12', 'ip': '10.1.12.100'}
                    ],
                'networks': ['10.1.0.0/24', '10.1.1.0/24'],
                'timers_bgp': [' 90', ' 30']
            }
        },
        'loopback': {
            'interface loopback 2': {
                'ipv4_address': '10.0.0.1/24',
                'ipv6_address': '2001::2/64'
                },
            'interface loopback 3': {
                'ipv4_address': '192.168.10.1/24',
                'ipv6_address': '2002::1/64'
                }
        },
         'sftp-server': {
                    'status':'enable'
        },
        'ip_routes': {
            '10.1.1.3':
                {
                    'via': '1',
                    'prefix': '32',
                    'network': '10.1.1.3'
                },
            '10.1.1.1':
                {
                    'via': '140.1.1.1',
                    'prefix': '32',
                    'network': '10.1.1.1'
                },
            '10.1.1.2':
                {
                    'via': '140.1.1.1',
                    'prefix': '32',
                    'network': '10.1.1.2'
                }
            '2020::2':
                {
                     'network': '2020::2',
                     'prefix': '128',
                     'via': '1'
                },
            '2020::3':
                {
                    'network': '2020::3',
                    'prefix': '128',
                    'via': '1'
                }
        },
        "syslog_remotes": {
            '0': {
                'remote_host': '10.0.0.10',
                'port': 514,
                'transport': 'tcp',
                'severity': 'debug'
            }
        }


        }
    """

    result = {}

    # Parsing loopback configurations in show run
    result['loopback'] = {}
    loopback = None
    show_loopback_id = re.compile('interface loopback\s+[0-9]+', re.DOTALL)
    loopback_list = show_loopback_id.findall(raw_result)
    if loopback_list:
        config_lines = raw_result.splitlines()
        for config in config_lines:
            config = config.strip()
            if re.match('.*interface loopback.*', config):
                loopback = loopback_list.pop(0)
                result['loopback'][loopback] = {}
            if loopback in result['loopback']:
                loopback_ipv4_ip = re.match(
                    r'.*ip address\s+(\d+.\d+.\d+.\d+\/\d+).*',
                    config)
                if 'ipv4_address' not in result['loopback'][loopback]:
                    if loopback_ipv4_ip:
                        loopback_ipv4_ip = loopback_ipv4_ip.group(1)
                        result['loopback'][loopback][
                            'ipv4_address'] = loopback_ipv4_ip
                loopback_ipv6 = re.match(r'.*ipv6 address\s+(.*)', config)
                if 'ipv6_address' not in result['loopback'][loopback]:
                    if loopback_ipv6:
                        loopback_ipv6 = loopback_ipv6.group(1)
                        result['loopback'][loopback][
                            'ipv6_address'] = loopback_ipv6

# bgp Section
    bgp_section_re = r'router bgp.*(?=!)'
    re_bgp_section = re.findall(bgp_section_re, raw_result, re.DOTALL)
    as_number_re = r'router bgp\s+(\d+)'
    router_id_re = r'\s+bgp router-id\s+(.*)'
    network_re = r'\s+network\s+(.*)'
    neighbour_re = r'\s+neighbor\s+(\S+)\s+(\S+)\s+(\d+)'
    timers_re = r'\s+timers bgp(\s+\d+)(\s+\d+)'
    re_as_number = None
    result['bgp'] = {}
    if re_bgp_section:
        for line in re_bgp_section[0].splitlines():
            re_result = re.match(as_number_re, line)
            if re_result:
                re_as_number = re_result.group(1)
                result['bgp'][re_as_number] = {}

            re_result = re.match(router_id_re, line)
            if re_result:
                result['bgp'][re_as_number]['router_id'] = re_result.group(1)

            re_result = re.match(network_re, line)
            if re_result:
                network = re_result.group(1)
                if 'networks' not in result['bgp'][re_as_number].keys():
                    result['bgp'][re_as_number]['networks'] = []
                    result['bgp'][re_as_number]['networks'].append(network)
                else:
                    result['bgp'][re_as_number]['networks'].append(network)
            re_result = re.match(timers_re, line)
            if re_result:
                timers = [re_result.group(1), re_result.group(2)]
                if 'timers_bgp' not in result['bgp'][re_as_number].keys():
                    result['bgp'][re_as_number]['timers_bgp'] = timers
                else:
                    result['bgp'][re_as_number]['timers_bgp'] = timers

            re_result = re.match(neighbour_re, line)
            if re_result:
                ip = re_result.group(1)
                neighbors = {'ip': ip, 'remote-as': re_result.group(3)}
                if 'neighbors' not in result['bgp'][re_as_number].keys():
                    result['bgp'][re_as_number]['neighbors'] = []
                    result['bgp'][re_as_number]['neighbors'].append(neighbors)
                else:
                    result['bgp'][re_as_number]['neighbors'].append(neighbors)

    # ospf Section
    ospf_section_re = r'router ospf(\n\s+.*)*'
    re_ospf_section = re.findall(ospf_section_re, raw_result, re.DOTALL)
    router_id_re = r'\s+router-id\s+(.*)'
    network_re = r'\s+network\s+(\d.+)\s+(area)\s+(\d.+)'
    max_metric_re = r'\s+max-metric router-lsa on-startup\s+(\d+)\s+'
    result['ospf'] = {}
    if re_ospf_section:
        for line in re_ospf_section[0].splitlines():
            re_result = re.match(router_id_re, line)
            if re_result:
                if 'router-id' not in result['ospf'].keys():
                    result['ospf']['router-id'] = re_result.group(1)

            re_result = re.match(network_re, line)
            if re_result:
                area_id = re_result.group(3)
                network = {'network': re_result.group(1), 'area': area_id}
                if 'networks' not in result['ospf'].keys():
                    result['ospf']['networks'] = []
                    result['ospf']['networks'].append(network)
                else:
                    result['ospf']['networks'].append(network)

            re_result = re.match(max_metric_re, line)
            if re_result:
                if 'max_lsa_startup' not in result['ospf'].keys():
                    result['ospf']['max_lsa_startup'] = re_result.group(1)
                else:
                    result['ospf']['max_lsa_startup'] = re_result.group(1)

    # vlan Section
    vlan_section_re = r'vlan\s+(\d+)\n(.*)'
    re_vlan_section = re.findall(vlan_section_re, raw_result)
    result['vlan'] = {}
    if re_vlan_section:
        for vlan_info in re_vlan_section:
            if "no shutdown" in vlan_info[1]:
                vlan_state = 'up'
            else:
                vlan_state = 'down'
            vlan = {'vlanid': vlan_info[0], 'admin': vlan_state}
            if vlan_info[0] not in result['vlan'].keys():
                result['vlan'][vlan_info[0]] = vlan
            else:
                result['vlan'][vlan_info[0]] = vlan

    # interface Section
    if_section_re = r'\s+int\w+(?:\s+\S+.*)*'
    re_interface_section = re.findall(if_section_re, raw_result, re.DOTALL)
    interface_vlan_re = r'\interface\s(vlan\d+)'
    interface_port_re = r'interface\s(\d+)'
    interface_mgmt_re = r'interface\smgmt'
    interface_lag_re = r'\s*interface\slag\s(\d+)'
    duplex_half_re = r'\s+duplex\shalf'
    ipv4_re = r'\s+ip address\s(\d.+)'
    stat_ip_re = r'\s+ip static\s(\S+)'
    nameserver_re = r'\s+nameserver\s(\S+)'
    ipv6_re = r'\s+ipv6 address\s(\S+)'
    lacp_re = r'\s+lacp\sport-(\w+)\s(\d+)'
    lag_re = r'\s+lag\s(\d+)'
    mtu_re = r'\s+mtu\s(\w+)'
    speed_re = r'\s+speed\s(\w+)'
    vrf_re = r'\s+vrf attach\s(\w+)'
    flow_ctl_re = r'\s+flowcontrol\s(\w+)\s(\w+)'
    no_shut_re = r'\s+no shutdown'
    no_routing_re = r'\s+no routing'
    no_lldp_re = r'\sno lldp\s(\w+)'
    vlan_trunk_re = r'\s+vlan trunk\s(\w+)\s(\d+)'
    vlan_access_re = r'\s+vlan access\s(\d+)'
    autoneg_re = r'\s+autonego\w+\s(\w+)'
    int_loopback_re = r'interface loopback\s+([0-9]+)'

    result['interface'] = {}
    if re_interface_section:
        port = None
        for line in re_interface_section[0].splitlines():
            # Check for blank line
            if line == '':
                continue

            # Check if interface is vlan
            if re.match(interface_vlan_re, line):
                re_result = re.match(interface_vlan_re, line)
                port = re_result.group(1)
                if port not in result['interface'].keys():
                    result['interface'][port] = {}

            # Check if interface is port
            elif re.match(interface_port_re, line):
                re_result = re.match(interface_port_re, line)
                port = re_result.group(1)
                if port not in result['interface'].keys():
                    result['interface'][port] = {}

            # Check if interface is mgmt or lag
            elif re.match(interface_lag_re, line):
                if 'lag' not in result['interface'].keys():
                    result['interface']['lag'] = {}
                    re_result = re.match(interface_lag_re, line)
                    port = re_result.group(1)
                    if port not in result['interface']['lag'].keys():
                        result['interface']['lag'][port] = {}

            elif re.match(interface_mgmt_re, line):
                if 'mgmt' not in result['interface'].keys():
                    result['interface']['mgmt'] = {}

            # Check if interface is loopback
            elif re.match(int_loopback_re, line):
                re_result = re.match(int_loopback_re, line)
                if re_result:
                    port = "loopback " + re_result.group(1)
                    if port not in result['interface'].keys():
                        result['interface'][port] = {}

            # Match nameserver
            re_result = re.match(nameserver_re, line)
            if re_result:
                if 'nameserver' not in result['interface']['mgmt'].keys():
                    result['interface']['mgmt']['nameserver'] =\
                        re_result.group(1)

            # Match mgmt static ip
            re_result = re.match(stat_ip_re, line)
            if re_result:
                if 'static' not in result['interface']['mgmt'].keys():
                    result['interface']['mgmt']['static'] =\
                        re_result.group(1)

            # Match autonegotiation
            re_result = re.match(autoneg_re, line)
            if re_result:
                result['interface'][port]['autonegotiation'] =\
                    re_result.group(1)

            # Match ipv4
            re_result = re.match(ipv4_re, line)
            if re_result:
                if result['interface'].get('lag'):
                    result['interface']['lag'][port]['ipv4'] = \
                        re_result.group(1)
                else:
                    result['interface'][port]['ipv4'] = re_result.group(1)

            # Match ipv6
            re_result = re.match(ipv6_re, line)
            if re_result:
                if result['interface'].get('lag'):
                    result['interface']['lag'][port]['ipv6'] = \
                        re_result.group(1)
                else:
                    result['interface'][port]['ipv6'] = re_result.group(1)

            # Match admin state
            re_result = re.match(no_shut_re, line)
            if re_result:
                result['interface'][port]['admin'] = 'up'

            # Match routing
            re_result = re.match(no_routing_re, line)
            if re_result:
                result['interface'][port]['routing'] = 'no'

            # Match duplex rate
            re_result = re.match(duplex_half_re, line)
            if re_result:
                result['interface'][port]['duplex'] = 'half'

            # Match lag
            re_result = re.match(lag_re, line)
            if re_result:
                result['interface'][port]['lag'] = re_result.group(1)

            # Match lldp
            re_result = re.match(no_lldp_re, line)
            if re_result:
                rx_tx = re_result.group(1)
                if 'lldp' not in result['interface'][port].keys():
                    result['interface'][port]['lldp'] = {}
                    result['interface'][port]['lldp'][rx_tx] = 'down'
                else:
                    result['interface'][port]['lldp'][rx_tx] = 'down'

            # Match mtu
            re_result = re.match(mtu_re, line)
            if re_result:
                result['interface'][port]['mtu'] = re_result.group(1)

            # Match speed
            re_result = re.match(speed_re, line)
            if re_result:
                result['interface'][port]['speed'] = re_result.group(1)

            # Match flowcontrol
            re_result = re.match(flow_ctl_re, line)
            if re_result:
                rx_or_tx = re_result.group(1)
                if 'flowcontrol' not in result['interface'][port].keys():
                    result['interface'][port]['flowcontrol'] = {}
                    result['interface'][port]['flowcontrol'][rx_or_tx] = 'on'
                else:
                    result['interface'][port]['flowcontrol'][rx_or_tx] = 'on'

            # Match vrf
            re_result = re.match(vrf_re, line)
            if re_result:
                result['interface'][port]['vrf'] = re_result.group(1)

            # Match vlan trunk
            re_result = re.match(vlan_trunk_re, line)
            if re_result:
                mtype = re_result.group(1)
                vlanid = re_result.group(2)
                vlan_info = {'mode': 'trunk', 'type': mtype, 'vlanid': vlanid}
                if 'vlan' not in result['interface'][port].keys():
                    result['interface'][port]['vlan'] = []
                    result['interface'][port]['vlan'].append(vlan_info)
                else:
                    result['interface'][port]['vlan'].append(vlan_info)

            # Match vlan access
            re_result = re.match(vlan_access_re, line)
            if re_result:
                vlan_access_info = {'mode': 'access',
                                    'vlanid': re_result.group(1)}
                if 'vlan' not in result['interface'][port].keys():
                    result['interface'][port]['vlan'] = []
                    result['interface'][port]['vlan'].append(vlan_access_info)
                else:
                    result['interface'][port]['vlan'].append(vlan_access_info)

            # Match lacp
            re_result = re.match(lacp_re, line)
            if re_result:
                if 'lacp' not in result['interface'][port].keys():
                    result['interface'][port]['lacp'] = {}
                if re_result.group(1) == 'id':
                    result['interface'][port]['lacp']['port-id'] =\
                        re_result.group(2)
                elif re_result.group(1) == 'priority':
                    result['interface'][port]['lacp']['priority'] =\
                        re_result.group(2)

    # sftp-server section
    result['sftp-server'] = {}
    sftp_server_re = r'(\s+sftp-server\s+)'
    sftp_status_re = r'(\s+(?P<status>enable)\s*)'
    re_server = re.search(sftp_server_re, raw_result)
    re_server_status = re.search(sftp_status_re, raw_result)
    if re_server:
        result_status = re_server_status.groupdict()
        for key, value in result_status.items():
            if value is not None:
                result['sftp-server'][key] = value

    # IP Routes section capture regex
    result['ip_routes'] = {}
    ip_routes_section_re = r'ipv?6? route.*'
    re_ip_routes_section = re.findall(ip_routes_section_re, raw_result,
                                      re.DOTALL)
    if re_ip_routes_section:
        ip_route_re = (
            r'ipv?6? route\s(?P<network>.*)'
            r'/(?P<prefix>\d+)\s'
            r'(?P<via>(?:.*))'
        )
        for line in re_ip_routes_section[0].splitlines():
            re_result = re.match(ip_route_re, line)
            partial = re_result.groupdict()
            for key, value in partial.items():
                partial[key] = value
            result['ip_routes'][partial['network']] = partial

    # Syslog Remote configuration
    result['syslog_remotes'] = {}
    re_syslog_config = (
        r'\s*logging\s*(?P<remote_host>\S+)\s*(?P<transport>'
        r'(tcp|udp))*\s*(?P<port>[0-9]+)*\s*((severity)\s*'
        r'(?P<severity>\S+))*'
    )
    syslog_configs = re.finditer(re_syslog_config, raw_result)

    remote_syslog = {}
    i = 0
    for line in syslog_configs:
        syslog_config = line.groupdict()
        remote_syslog[str(i)] = {}
        for key, value in syslog_config.items():
            if value is not None:
                remote_syslog[str(i)][key] = value

        i += 1

    result['syslog_remotes'] = remote_syslog

    return result


def parse_show_ip_route(raw_result):
    """
    Parse the 'show ip route' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: list
    :return: The parsed result of the show ip route command in a \
        list of dictionaries of the form:

     ::

        [
            {
                'id': '140.0.0.0',
                'prefix': '30',
                'next_hops': [
                    {
                        'via': '10.10.0.2',
                        'distance': '20',
                        'from': 'bgp',
                        'metric': '0'
                    }
                ]
            },
            {
                'id': '10.10.0.0',
                'prefix': '24',
                'next_hops': [
                    {
                        'via': '1',
                        'distance': '0',
                        'from': 'connected',
                        'metric': '0'
                    }
                ]
            },
            {
                'id': '193.0.0.2',
                'prefix': '32',
                'next_hops': [
                    {
                        'via': '50.0.0.2',
                        'distance': '1',
                        'from': 'static',
                        'metric': '0'
                    },
                    {
                        'via': '56.0.0.3',
                        'distance': '1',
                        'from': 'static',
                        'metric': '0'
                    }
                ]
            }
        ]
    """

    ipv4_network_re = (
        r'(?P<network>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)'
    )

    ipv4_nexthop_re = (
        r'via\s+(?P<via>(?:\d+\.\d+\.\d+\.\d+|[a-z0-9]+)),\s+'
        r'\[(?P<distance>\d+)/(?P<metric>\d+)\],\s+(?P<from>\S+)'
    )

    result = []

    lines = raw_result.splitlines()
    line_index = 0

    while line_index < len(lines):
        re_result = re.search(ipv4_network_re, lines[line_index])

        if re_result:
            network = {}
            partial = re_result.groupdict()

            network['id'] = partial['network']
            network['prefix'] = partial['prefix']

            network['next_hops'] = []
            check_for_next_hops = True

            line_index += 1

            while (check_for_next_hops and line_index < len(lines)):
                re_result = re.search(
                    ipv4_nexthop_re,
                    lines[line_index]
                )

                if re_result:
                    partial = re_result.groupdict()

                    network['next_hops'].append(partial)
                    line_index += 1
                else:
                    check_for_next_hops = False

            result.append(network)
        else:
            line_index += 1

    return result


def parse_show_ipv6_route(raw_result):
    """
    Parse the 'show ipv6 route' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: list
    :return: The parsed result of the show ipv6 route command in a \
        list of dictionaries of the form:

     ::

        [
            {
                'id': '140.0.0.0',
                'prefix': '30',
                'next_hops': [
                    {
                        'via': '10.10.0.2',
                        'distance': '20',
                        'from': 'bgp',
                        'metric': '0'
                    }
                ]
            },
            {
                'id': '10.10.0.0',
                'prefix': '24',
                'next_hops': [
                    {
                        'via': '1',
                        'distance': '0',
                        'from': 'connected',
                        'metric': '0'
                    }
                ]
            },
            {
                'id': '193.0.0.2',
                'prefix': '32',
                'next_hops': [
                    {
                        'via': '50.0.0.2',
                        'distance': '1',
                        'from': 'static',
                        'metric': '0'
                    },
                    {
                        'via': '56.0.0.3',
                        'distance': '1',
                        'from': 'static',
                        'metric': '0'
                    }
                ]
            }
        ]
    """

    ipv6_network_re = (
        r'(?P<selected>\*?)'
        r'(?P<network>(?:(?:(?:[0-9A-Za-z]+:)+:?([0-9A-Za-z]+)?)+)/\d+)'
    )

    ipv6_nexthop_re = (
        r'via\s+(?P<via>(?:(?:(?:[0-9A-Za-z]+:)+:?([0-9A-Za-z]+)?)+|[a-zA-Z0-9'
        r']+)),\s+\[(?P<distance>[a-z0-9]+)/(?P<metric>\d+)\],\s+(?P<from>\S+)'
    )

    result = []

    lines = raw_result.splitlines()
    line_index = 0

    while line_index < len(lines):
        re_result = re.search(ipv6_network_re, lines[line_index])

        if re_result:
            network = {}
            partial = re_result.groupdict()

            network['id'] = partial['network']

            network['next_hops'] = []
            check_for_next_hops = True

            line_index += 1

            while (check_for_next_hops and line_index < len(lines)):
                re_result = re.search(
                    ipv6_nexthop_re,
                    lines[line_index]
                )

                if re_result:
                    partial = re_result.groupdict()

                    network['next_hops'].append(partial)
                    line_index += 1
                else:
                    check_for_next_hops = False

            result.append(network)
        else:
            line_index += 1

    return result


def parse_show_ip_ecmp(raw_result):
    """
    Parse the 'show ip ecmp' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ip ecmp in a \
        dictionary of the form:

    ::

        {
            'global_status': True,
            'resilient': False,
            'src_ip': True,
            'dest_ip': True,
            'src_port': True,
            'dest_port': True
        }
    """

    show_ip_ecmp_re = (
        r'\s*ECMP Configuration\s*-*\s*'
        r'ECMP Status\s*: (?P<global_status>\S+)\s*'
        r'(Resilient Hashing\s*: (?P<resilient>\S+))?\s*'
        r'ECMP Load Balancing by\s*-*\s*'
        r'Source IP\s*: (?P<src_ip>\S+)\s*'
        r'Destination IP\s*: (?P<dest_ip>\S+)\s*'
        r'Source Port\s*: (?P<src_port>\S+)\s*'
        r'Destination Port\s*: (?P<dest_port>\S+)\s*'
    )

    re_result = re.match(show_ip_ecmp_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if value == 'Enabled':
                result[key] = True
            elif value == 'Disabled':
                result[key] = False

    return result


def parse_show_ntp_associations(raw_result):
    """
    Parse the 'show ntp associations' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ntp associations command in a \
        dictionary of the form:

     ::

        {
            '1': { 'code': '*',
                   'id': '1'
                   'name': '192.168.1.100',
                   'remote': '192.168.1.100',
                   'version': '3',
                   'key_id': '-',
                   'reference_id': '172.16.135.123',
                   'stratum': '4',
                   'type': 'U',
                   'last': '41',
                   'poll': '64',
                   'reach': '377',
                   'delay': '0.138',
                   'offset': '17.811',
                   'jitter': '1.942'
            },
            '2': { 'code': ' ',
                   'id': '2'
                   'name': '192.168.1.101',
                   'remote': '192.168.1.101',
                   'version': '3',
                   'key_id': '10',
                   'reference_id': '172.16.135.123',
                   'stratum': '4',
                   'type': 'U',
                   'last': '50',
                   'poll': '64',
                   'reach': '377',
                   'delay': '0.162',
                   'offset': '-1.749',
                   'jitter': '8.429'
            }
        }
    """

    ntp_asssociations_re = (
        r'(?P<code>\D)\s+(?P<id>\d+)\s+(?P<name>\S+)\s+'
        r'(?P<remote>\S+)\s+(?P<version>\d+)\s+(?P<key_id>\S+)\s+'
        r'(?P<reference_id>\S+)\s+(?P<stratum>\S+)\s+(?P<type>\S+)\s+'
        r'(?P<last>\S+)\s+(?P<poll>\S+)\s+(?P<reach>\S+)\s+'
        r'(?P<delay>\S+)\s+(?P<offset>\S+)\s+(?P<jitter>\S+)'
    )

    result = {}
    for line in raw_result.splitlines():
        re_result = re.search(ntp_asssociations_re, line)
        if re_result:
            partial = re_result.groupdict()
            result[partial['id']] = partial

    return result


def parse_show_ntp_authentication_key(raw_result):
    """
    Parse the 'show ntp authentication-keys' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ntp authentication-keys command \
        in a dictionary of the form:

     ::

        {
            '10': { 'key_id': '10',
                    'md5_password': 'MyPassword'
            },
            '11': { 'key_id': '11',
                    'md5_password': 'MyPassword_2'
            }
        }
    """

    ntp_authentication_key_re = (
        r'\s(?P<key_id>\d+)\s+(?P<md5_password>\S+)'
    )

    result = {}
    for line in raw_result.splitlines():
        re_result = re.search(ntp_authentication_key_re, line)
        if re_result:
            partial = re_result.groupdict()
            result[partial['key_id']] = partial

    return result


def parse_show_ntp_statistics(raw_result):
    """
    Parse the 'show ntp statistics' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ntp statistics command \
        in a dictionary of the form:

     ::

        {
            'rx_pkts': 234793,
            'cur_ver_rx_pkts' : 15,
            'old_ver_rx_pkts' : 191,
            'error_pkts' : 16,
            'auth_failed_pkts' : 17,
            'declined_pkts' : 18,
            'restricted_pkts' : 19,
            'rate_limited_pkts' : 20,
            'kod_pkts' : 21
        }
    """

    ntp_statistics_re = (
        r'\s*Rx-pkts\s*(?P<rx_pkts>\d+)\s*'
        r'Cur\sVer\sRx-pkts\s*(?P<cur_ver_rx_pkts>\d+)\s*'
        r'Old\sVer\sRx-pkts\s*(?P<old_ver_rx_pkts>\d+)\s*'
        r'Error\spkts\s*(?P<error_pkts>\d+)\s*'
        r'Auth-failed\spkts\s*(?P<auth_failed_pkts>\d+)\s*'
        r'Declined\spkts\s*(?P<declined_pkts>\d+)\s*'
        r'Restricted\spkts\s*(?P<restricted_pkts>\d+)\s*'
        r'Rate-limited\spkts\s*(?P<rate_limited_pkts>\d+)\s*'
        r'KOD\spkts\s*(?P<kod_pkts>\d+)\s*'
    )

    re_result = re.match(ntp_statistics_re, raw_result)

    result = re_result.groupdict()
    for key, value in result.items():
        if value and value.isdigit():
            result[key] = int(value)

    return result


def parse_show_ntp_status(raw_result):
    """
    Parse the 'show ntp status' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ntp status command \
        in a dictionary of the form:

     ::

        {
            'status': 'enabled',
            'authentication_status' : 'disabled',
            'uptime' : 2343,
            'server' : '192.168.1.100',
            'stratum' : '4',
            'poll_interval' : '64',
            'time_accuracy' : '17.811',
            'reference_time' : 'Mon Feb 15 2016 16:59:20.909 (UTC)'
        }
    """

    ntp_status_re = (
        r'\s*NTP\sis\s*(?P<status>\w+)\s*'
        r'NTP\sauthentication\sis\s*(?P<authentication_status>\w+)\s*'
        r'Uptime:\s*(?P<uptime>\d+)\s*'
    )

    ntp_status_synchronized_re = (
        r'\s*Synchronized\sto\sNTP\sServer\s*(?P<server>\S+)\s*'
        r'at\sstratum\s*(?P<stratum>\d+)\s*'
        r'Poll\sinterval\s=\s*(?P<poll_interval>\d+)\s*seconds\s*'
        r'Time\saccuracy\sis\swithin\s*(?P<time_accuracy>\S+)\s*seconds\s*'
        r'Reference\stime:\s*(?P<reference_time>[\S+\s*]{34})\s*'
    )

    result = {}
    re_result = re.match(ntp_status_re, raw_result)
    result = re_result.groupdict()
    result['uptime'] = int(result['uptime'])

    re_result_synchronized = re.search(ntp_status_synchronized_re, raw_result)
    if re_result_synchronized is not None:
        result_synchronized = re_result_synchronized.groupdict()
        for key, value in result_synchronized.items():
            result[key] = value

    return result


def parse_show_ntp_trusted_keys(raw_result):
    """
    Parse the 'show ntp trusted-keys' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ntp trusted-keys command \
        in a dictionary of the form:

     ::

        {
            '11': { 'key_id': '11' },
            '12': { 'key_id': '12' }
        }
    """

    ntp_trusted_key_re = (
        r'(?P<key_id>\d+)'
    )

    result = {}
    for line in raw_result.splitlines():
        re_result = re.search(ntp_trusted_key_re, line)
        if re_result:
            partial = re_result.groupdict()
            result[partial['key_id']] = partial

    return result


def parse_show_dhcp_server_leases(raw_result):
    """
    Parse the 'show dchp-server leases' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show dhcp-server leases command \
        in a dictionary of the form:

     ::

        {
            '192.168.10.10':
            {
                   'expiry_time': 'Thu Mar  3 05:36:11 2016',
                   'mac_address': '00:50:56:b4:6c:36',
                   'ip_address': '192.168.10.10',
                   'hostname': 'cl02-win8',
                   'client_id': '*'
             },
            '192.168.20.10':
            {
                   'expiry_time': 'Wed Sep 23 23:07:12 2015',
                   'mac_address': '10:55:56:b4:6c:c6',
                   'ip_address': '192.168.20.10',
                   'hostname': '95_h1',
                   'client_id': '*'
             }
        }
    """

    dhcp_server_leases_re = (
        r'\n+(?P<expiry_time>[\S+\s*]{24})\s+(?P<mac_address>\S+)\s+'
        r'(?P<ip_address>\S+)\s+(?P<hostname>\S+)\s+(?P<client_id>\S+)'
    )

    result = {}
    for re_result in re.finditer(dhcp_server_leases_re, raw_result):
        lease = re_result.groupdict()
        result[lease['ip_address']] = lease
    return result


def parse_show_dhcp_server(raw_result):
    """
    Parse the 'show dhcp-server' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show ntp trusted-keys command \
        in a dictionary of the form:

     ::

        {
            'pools': [
                {
                    'pool_name': 'CLIENTS-VLAN60',
                    'start_ip': '192.168.60.10',
                    'end_ip': '192.168.60.250',
                    'netmask': '255.255.255.0',
                    'broadcast': '192.168.60.255',
                    'prefix_len': '*',
                    'lease_time': '1440',
                    'static_bind': 'False',
                    'set_tag': '*',
                    'match_tag': '*'
                }
            ],
            'static': [
                {
                    'static_ip': '192.168.20.48',
                    'hostname': '*',
                    'client_id': '*',
                    'lease_time': '1440',
                    'mac_address': 'aa:bb:cc:dd:ee:ff',
                    'set_tag': '*'
                },
                {
                    'static_ip': '10.2.2.2',
                    'hostname': '*',
                    'client_id': '*',
                    'lease_time': '1440',
                    'mac_address': '11:11:11:11:11:11',
                    'set_tag': '*'
                }
            ],
            'options': [
                {
                    'option_number': '15',
                    'option_name': '*',
                    'option_value': 'tigerlab.ntl.com',
                    'ipv6_option': 'False',
                    'match_tags': '*'
                },
                {
                    'option_number': '*',
                    'option_name': 'Router',
                    'option_value': '192.168.60.254',
                    'ipv6_option': 'False',
                    'match_tags': '*'
                },
                {
                    'option_number': '6',
                    'option_name': '*',
                    'option_value': '10.100.205.200',
                    'ipv6_option': 'False',
                    'match_tags': '*'
                }
            ]
        }
    """

    dhcp_dynamic_re = (
        r'(?P<pool_name>[\w_\-]+)'
        r'\s+(?P<start_ip>[\d\.:a-fA-F]+)'
        r'\s+(?P<end_ip>[\d\.:a-fA-F]+)'
        r'\s+(?P<netmask>[\d\.*]+)'
        r'\s+(?P<broadcast>[\d\.*]+)'
        r'\s+(?P<prefix_len>[\w\*/]+)'
        r'\s+(?P<lease_time>[\d]+)'
        r'\s+(?P<static_bind>True|False)'
        r'\s+(?P<set_tag>[\w\*]+)'
        r'\s+(?P<match_tag>[\w\*]+)'
    )

    dhcp_static_re = (
        r'(?P<static_ip>[\d\.:a-fA-F]+)'
        r'\s+(?P<hostname>[\w\*]+)'
        r'\s+(?P<client_id>[\w\*]+)'
        r'\s+(?P<lease_time>[\d]+)'
        r'\s+(?P<mac_address>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))'
        r'\s+(?P<set_tag>[\w\*]+)'
    )

    dhcp_options_re = (
        r'\n(?P<option_number>[\d\*]+)'
        r'\s+(?P<option_name>\S+)'
        r'\s+(?P<option_value>\S+)'
        r'\s+(?P<ipv6_option>True|False)'
        r'\s+(?P<match_tags>[\w\*]+)'
    )

    result = {}
    pools_list = []
    static_list = []
    options_list = []
    for output in re.finditer(dhcp_dynamic_re, raw_result):
        dhcp_dynamic = output.groupdict()
        pools_list.append(dhcp_dynamic)
    result['pools'] = pools_list
    for output in re.finditer(dhcp_static_re, raw_result):
        dhcp_static = output.groupdict()
        static_list.append(dhcp_static)
    result['static'] = static_list
    for output in re.finditer(dhcp_options_re, raw_result):
        dhcp_options = output.groupdict()
        options_list.append(dhcp_options)
    result['options'] = options_list

    assert result
    return result


def parse_show_sflow(raw_result):
    """
    Parse the 'show sflow' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show sflow command in a \
       dictionary of the form:

     ::

            {
                'sflow': 'enabled',
                'collector':[
                    {
                        'ip': '10.10.11.2',
                        'port': '6343',
                        'vrf': 'vrf_default'
                    },
                    {
                        'ip': '10.10.12.2',
                        'port': '6344',
                        'vrf': 'vrf_default'
                    }
                ],
                'agent_interface': '3',
                'agent_address_family': 'ipv4',
                'sampling_rate': 20,
                'polling_interval': 30,
                'header_size': 128,
                'max_datagram_size': 1400,
                'number_of_samples': 10
            }
    """

    sflow_info_re = (
         r'\s*sFlow\s*Configuration\s*'
         r'\s*-----------------------------------------\s*'
         r'\s*sFlow\s*(?P<sflow>\S+)\s*'
         r'Collector\sIP/Port/Vrf\s*(?P<collector>.+)'
         r'Agent\sInterface\s*(?P<agent_interface>.+)'
         r'Agent\sAddress\sFamily\s*(?P<agent_address_family>Not set|ipv4|ipv6)\s*'  # noqa
         r'Sampling\sRate\s*(?P<sampling_rate>\d+)\s*'
         r'Polling\sInterval\s*(?P<polling_interval>\d+)\s*'
         r'Header\sSize\s*(?P<header_size>\d+)\s*'
         r'Max\sDatagram\sSize\s*(?P<max_datagram_size>\d+)\s*'
         r'Number\sof\sSamples\s*(?P<number_of_samples>\d+)\s*'
    )

    re_result = re.match(sflow_info_re, raw_result, re.DOTALL)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value and value.isdigit():
            result[key] = int(value)
    result['agent_interface'] = result['agent_interface'].strip()
    if str(result['collector']) != 'Not set':
        count = result['collector'].count('\n')
        result['collector'] = \
            result['collector'].split('\n', count - 1)
        result['collector'] = \
            [x.strip(' \n') for x in result['collector']]
        for i in range(0, count):
            result['collector'][i] = \
                result['collector'][i].split('/', 2)
            result['collector'][i] = \
                dict(zip(['ip', 'port', 'vrf'], result['collector'][i]))

    return result


def parse_show_vlog_config(raw_result):
    """
    Parse the 'show vlog config' command raw output.

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog config command.
            : True on Success or False on Failure.
    """
    show_vlog_config_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(show_vlog_config_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "Feature" and "Daemon" and "Syslog" in line:
                return True
    return False


def parse_show_vlog_config_daemon(raw_result):
    """
    Parse the 'show vlog config daemon' command raw output.

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog config daemon command.
            : True on success or False on Failure.
    """
    show_config_daemon_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(show_config_daemon_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "ops-lldpd" and "WARN" in line:
                return True
    return False


def parse_show_vlog_config_feature(raw_result):
    """
    Parse the 'show vlog config feature' command raw output.

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog config feature command.
            : True on success or False on Failure.
    """
    show_config_feature_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(show_config_feature_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "lacp" and "ERR" in line:
                return True
    return False


def parse_show_vlog_config_list(raw_result):
    """
    Parse the 'show vlog config list' command raw output.

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog config list command.
            : True on success or False on Failure.
    """
    show_config_list_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(show_config_list_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "Features" and "Description" in line:
                return True
    return False


def parse_show_vlog_daemon(raw_result):
    """
    Parse the 'show vlog daemon' command raw output.

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog daemon command.
            : True on success or False on Failure.
    """
    show_daemon_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(show_daemon_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "ops-ledd (OpenSwitch ledd)" in line:
                return True
            else:
                if "No match for the filter provided" in line:
                    return False
    return False


def parse_show_vlog_severity(raw_result):
    """
    Parse the 'show vlog severity' command raw output.

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog severity command.
            : True on success or False on Failure.
    """
    show_severity_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(show_severity_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "WARN" in line:
                return True
            else:
                if "Unknown command" in line:
                    return False
    return False


def parse_show_vlog_daemon_severity(raw_result):
    """
    Parse the 'show vlog daemon {daemon} severity {severity}' command output

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog daemon {daemon} severity \
            {severity} command.
            : True on success or False on Failure.
    """
    daemon_severity_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(daemon_severity_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "INFO" and "(ops-portd)" in line:
                return True
            else:
                if "No match for the filter provided" in line:
                    return False
    return False


def parse_show_vlog_severity_daemon(raw_result):
    """
    Parse the 'show vlog severity {severity} daemon {daemon}' command output

    :param str raw_result: vtysh raw result string.
    :return: The parsed result of the show vlog severity {severity} daemon \
            {daemon} command.
            : True on success or False on Failure.
    """
    return parse_show_vlog_daemon_severity(raw_result)


def parse_show_vlog(raw_result):
    """
    Parse the 'show vlog {sub-command}' command raw output

    :param str raw_result: vtysh raw result string.
    :return: True or False.
    """
    vlog_re = (
        r'([-\w_]+)\s*([-\w_]+)*\s*([-\w_]+)\s*([-\w_]+)'
    )
    re_result = {}
    for line in raw_result.splitlines():
        re_result = re.search(vlog_re, raw_result)
        if re_result is None:
            assert False
        else:
            if "ovs" in line:
                return False
            else:
                if "Unknown command" in line:
                    return True
    return False


def parse_show_startup_config(raw_result):
    """
    Parse the 'show startup-config' command raw output.
    This parser currently returns only sftp-server section
    of the show-startup command.
    Followed the same rule as per running config library parser.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show running-config
        command in a dictionary of the form:

     ::
        {
        'sftp-server': {
        'status':'enable'}
        }
    """
    return parse_show_running_config(raw_result)


def parse_show_tftp_server(raw_result):
    """
    Parse the 'show tftp-server' command raw output.
    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show tftp-server\
        in a dictionary of the form:

    ::

        {
            'tftp_server' : 'Enabled',
            'tftp_server_secure_mode' : 'Enabled',
            'tftp_server_file_path' : '/tmp/'
        }
    """

    show_tfpt_server_re = (
        r'\s*TFTP server configuration\s*-*\s*'
        r'TFTP server\s*:\s+(?P<tftp_server>\S+)\s*'
        r'TFTP server secure mode\s*:\s+(?P<tftp_server_secure_mode>\S+)\s*'
        r'TFTP server file path\s*:\s+(?P<tftp_server_file_path>\S+)'
    )

    re_result = re.match(show_tfpt_server_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if key == 'tftp_server' or key == 'tftp_server_secure_mode':
                if value == 'Enabled':
                    result[key] = True
                elif value == 'Disabled':
                    result[key] = False

    return result


def parse_show_core_dump(raw_result):
    """
    Parse the show core-dump output
    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show core-dump\
        in a dictionary of the form:

    ::

        {
            0:{
                'instance_id': 1202,
                'timestamp': '2016-04-19 08:12:11',
                'crash_reason': 'Segmentation Fault',
                'daemon_name': 'ops-fand'
            }
        }
    """

    show_re = (
        r'\s*(?P<daemon_name>\S+)'
        r'\s*(?P<instance_id>\S+)'
        r'\s*(?P<crash_reason>.{1,30})'
        r'\s*(?P<timestamp>[0-9\s:-]{18,20})'
    )

    show_re_kernel = (
        r'\s*(?P<daemon_name>\S+)'
        r'\s*(?P<timestamp>[0-9\s:-]{18,20})'
    )
    if "No core dumps are present" in raw_result:
        return {}

    result = {}
    core_dump_count = 0
    coredumps = raw_result.splitlines()
    for line in coredumps:
        if("Total number of core dumps" in line):
            break
        elif("=====" in line or "Crash Reason" in line):
            continue
        else:
            if "kernel" in line:
                re_result = re.match(show_re_kernel, line)
            else:
                re_result = re.match(show_re, line)

            assert re_result

            coredump_result = re_result.groupdict()

            if "kernel" in line:
                coredump_result['crash_reason'] = 'unknown'
                coredump_result['instance_id'] = '1'

            for key, value in coredump_result.items():
                if value is not None:
                    if value.isdigit():
                        coredump_result[key] = int(value)
                    else:
                        coredump_result[key] = value.strip()
            result[core_dump_count] = coredump_result
            core_dump_count += 1
    return result


def parse_config_tftp_server_enable(raw_result):
    """
    Parse the 'enable' command raw output in tftp-server context
    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the 'enable' in tftp-server\
        context:

    ::

        {
            '\s*TFTP server is enabled successfully\s*-*\s*'
        }
    """

    enable_tfpt_server_re = (
        r'TFTP server is\s(?P<result>\S*)\s*'
    )

    re_result = re.match(enable_tfpt_server_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if key == 'result':
                if value == 'already' or value == 'enabled':
                    result[key] = True
                else:
                    result[key] = False

    return result


def parse_config_tftp_server_no_enable(raw_result):
    """
    Parse the 'no enable' command raw output in tftp-server context
    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the 'no enable' in tftp-server\
        context:

    ::

        {
            '\s*TFTP server is enabled successfully\s*-*\s*'
        }
    """

    enable_tfpt_server_re = (
        r'TFTP server is\s(?P<result>\S*)\s*'
    )

    re_result = re.match(enable_tfpt_server_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if key == 'result':
                if value == 'already' or value == 'disabled':
                    result[key] = True
                else:
                    result[key] = False

    return result


def parse_config_tftp_server_path(raw_result):
    """
    Parse the 'path {path}' command raw output in tftp-server context
    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the 'no enable' in tftp-server\
        context:

    ::

        {
            'TFTP server path is added successfully'
        }
    """

    enable_tfpt_server_re = (
        r'TFTP server path is\s(?P<result>\S*)\s*'
    )

    re_result = re.match(enable_tfpt_server_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if key == 'result':
                if value == 'added':
                    result[key] = True
                else:
                    result[key] = False

    return result


def parse_config_tftp_server_no_path(raw_result):
    """
    Parse the 'no path {path}' command raw output in tftp-server context
    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the 'no enable' in tftp-server\
        context:

    ::

        {
            'TFTP server path is deleted successfully'
        }
    """

    enable_tfpt_server_re = (
        r'TFTP server path is\s(?P<result>\S*)\s*'
    )

    re_result = re.match(enable_tfpt_server_re, raw_result)
    assert re_result

    result = re_result.groupdict()
    for key, value in result.items():
        if value is not None:
            if key == 'result':
                if value == 'deleted':
                    result[key] = True
                else:
                    result[key] = False

    return result


def parse_show_mirror(raw_result):
    """
    Parse the 'show mirror' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show mirror command in a \
        dictionary of the form. Returns None if no mirror found:

    for 'show mirror':

     ::

        {
            'My_Session_1': {'name': 'My_Session_1',
                             'status': 'active'},
            'Other-Session-2': {'name': 'Other-Session-2',
                                'status': 'shutdown'}
        }

    for 'show mirror <name>':

     ::

        {
            'name': 'My_Session_1',
            'status': 'active',
            'source': [{'type': 'interface',
                        'id:' '2',
                        'direction': 'both'},
                       {'type': 'interface',
                        'id:' '3',
                        'direction': 'rx'}],
            'destination': {'type': 'interface',
                            'id:' '1'},
            'output_packets': '123456789'
            'output_bytes': '8912345678'
        }
    """

    mirror_list_header_re = (r'\s*name\s+status')
    mirror_list_re = (r'^\s*(?!name|-+\s)(?P<name>\S+)\s+(?P<status>\S+)')
    mirror_re = (
        r'\s*Mirror\sSession:\s+(?P<name>\S+)\s*'
        r'\s*Status:\s+(?P<status>\w+)(?:\s|.)*'
        r'\s*Output\sPackets:\s+(?P<output_packets>\d+)\s*'
        r'\s*Output\sBytes:\s+(?P<output_bytes>\d+)'
    )
    mirror_sorce_re = (
        r'Source:\s+(?P<type>\w+)\s+(?P<id>\w+)\s+(?P<direction>\w+)'
    )
    mirror_destination_re = (
        r'Destination:\s+(?P<type>\w+)\s+(?P<id>\S+)'
    )

    result = {}

    if re.match(mirror_list_header_re, raw_result, re.IGNORECASE):
        for line in raw_result.splitlines():
            re_result = re.search(mirror_list_re, line)
            if re_result:
                partial = re_result.groupdict()
                result[partial['name']] = partial
    else:
        re_result = re.match(mirror_re, raw_result)
        assert re_result
        result = re_result.groupdict()
        for key, value in result.items():
            if value and value.isdigit():
                result[key] = int(value)

        result['source'] = []
        for line in raw_result.splitlines():
            re_result = re.search(mirror_sorce_re, line)
            if re_result:
                partial = re_result.groupdict()
                result['source'].append(partial)

        result['destination'] = []
        for line in raw_result.splitlines():
            re_result = re.search(mirror_destination_re, line)
            if re_result:
                partial = re_result.groupdict()
                result['destination'] = partial

    if result == {}:
        return None
    else:
        return result


def parse_show_snmp_community(raw_result):
    """
    Parse the 'show snmp community' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: list
    :return: The parsed result of the show snmp community\
       command in a list of strings

    ::

        [
            'public',
            'private',
            'community1',
            'community2'

        ]
    """
    pattern_found = 0
    result = []
    res = 0
    for line in raw_result.splitlines():
        if pattern_found == 2:
            result.append(line.strip())
        else:
            res = re.match(r'\s*-+\s*', line)
            if res:
                pattern_found = pattern_found + 1
    if result == {}:
        return None
    else:
        return result


def parse_show_snmp_system(raw_result):
    """
    Parse the 'show snmp system' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show snmp system\
       command in a dictionary of the form

    ::

        {
             'System description' : 'OpenSwitchsystem
             'System location'    : 'Bangalore'
             'System contact'     :  'xyz@id.com'
        }
    """
    snmp_system_re = (
        r'\s*SNMP\ssystem\sinformation\s*'
        r'\s*-*\s*'
        r'\s*System\sdescription\s\:\s*(?P<system_description>.+)'
        r'\s*System\slocation\s\:\s*(?P<system_location>.+)'
        r'\s*System\scontact\s\:\s*(?P<system_contact>.+)'
    )

    re_result = re.match(snmp_system_re, raw_result)
    if re_result is None:
        return re_result

    result = re_result.groupdict()
    return result


def parse_show_snmp_trap(raw_result):
    """
    Parse the 'show snmp trap' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show snmp trap\
       command in a dictionary of the form

    ::

        {
            '20.2.2.2':{'Port':'455',
                       'Type':'inform',
                       'Version':'v2c',
                       'SecName':'testcom'
            },
            '10.1.1.1':{'Port':'162',
                       'Type':'trap',
                       'Version':'v1',
                       'SecName':'public'
            }
        }
    """
    pattern_found = 0
    result = []
    output = {}
    res = 0
    for line in raw_result.splitlines():
        if pattern_found == 2:
            result.append(line)
        else:
            res = re.match(r'\s*-+\s*', line)
            if res:
                pattern_found = pattern_found + 1
    for line in result:
        res = re.split(r'\s+', line)
        output[res[0]] = {'Port': res[1], 'Type': res[2], 'Version': res[3],
                          'SecName': res[4]}
    if output == {}:
        return None
    else:
        return output


def parse_diag_dump_lacp_basic(raw_result):
    """
    Parse the 'diag-dump lacp basic' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the getlacpinterfaces in a dictionary of the
       form:

     ::

         {
            'Interfaces':
                {
                    Return of parse_diag_dump_lacp_basic_interfaces
                }
            'Counters':
                {
                    Return of parse_diag_dump_lacp_basic_counters
                }
            'State':
                {
                    Return of parse_diag_dump_lacp_basic_counters
                }
        }
    """
    result_block = raw_result.split('\n\n')
    result = {}
    for block in result_block:
        if block.split('\n')[0] == 'LAG interfaces: ':
            result['Interfaces'] = parse_diag_dump_lacp_basic_interfaces(block)
        elif block.split('\n')[0] == 'LACP PDUs counters: ':
            block = '\n'.join(block.split('\n')[1:])
            result['Counters'] = parse_diag_dump_lacp_basic_counters(block)
        elif block.split('\n')[0] == 'LACP state: ':
            block = '\n'.join(block.split('\n')[1:])
            result['State'] = parse_diag_dump_lacp_basic_state(block)
    return result


def parse_diag_dump_lacp_basic_counters(raw_result):
    """
    Parse the 'diag-dump lacp basic' command raw output related to LACP
    counters.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the getlacpcounters in a dictionary of the
             form:

     ::

         {
            'lag':
                {'interface':
                    {'lacp_pdus_sent': 0,
                    'marker_response_pdus_sent': 0,
                    'lacp_pdus_received' : 0,
                    'marker_pdus_received' : 0},
                'interface':
                    {'lacp_pdus_sent': 0,
                    'marker_response_pdus_sent': 0,
                    'lacp_pdus_received' : 0,
                    'marker_pdus_received' : 0},
                }
        }
    """

    getlacpcounters_re = (
        r'Interface: (?P<interface>\d+)\s*'
        r'lacp_pdus_sent: (?P<lacp_pdus_sent>\d+)\s*'
        r'marker_response_pdus_sent: (?P<marker_response_pdus_sent>\d+)\s*'
        r'lacp_pdus_received: (?P<lacp_pdus_received>\d+)\s*'
        r'marker_pdus_received: (?P<marker_pdus_received>\d+)\s*'
    )

    result = {}
    result_interface = {}

    lag_block = raw_result.split('LAG lag')
    for block in lag_block:
        lag_id = block.split(':\n')[0]
        if lag_id:
            for re_partial in re.finditer(getlacpcounters_re, block):
                interface = re_partial.groupdict()
                interface_number = interface['interface']
                del interface['interface']
                for key, value in interface.items():
                    if value is None:
                        interface[key] = 0
                    elif value.isdigit():
                        interface[key] = int(value)
                result_interface[interface_number] = interface
            result[lag_id] = result_interface
            result_interface = {}
    return result


def parse_diag_dump_lacp_basic_state(raw_result):
    """
    Parse the 'diag-dump lacp basic' command raw output related to LACP
    state.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the getlacpstate in a dictionary of the
             form:

     ::

         {
            'lag':
                {'interface':
                    { 'actor_oper_port_state':
                        {'lacp_activity': 0,
                        'time_out': 0,
                        'aggregation' : 0,
                        'sync' : 0
                        'collecting': 0,
                        'distributing' : 0,
                        'defaulted' : 0,
                        'expired' : 0},
                    'partner_oper_port_state':
                        {'lacp_activity': 0,
                        'time_out': 0,
                        'aggregation' : 0,
                        'sync' : 0
                        'collecting': 0,
                        'distributing' : 0,
                        'defaulted' : 0,
                        'expired' : 0},
                    'lacp_control':
                        {'begin': 0,
                        'actor_churn': 0,
                        'partner_churn' : 0,
                        'ready_n' : 0
                        'selected': 0,
                        'port_moved' : 0,
                        'ntt' : 0,
                        'port_enabled' : 0},
                    }
                }
        }
    """

    getlacpstate_actor_re = (
        r'Interface: (?P<interface>\d+)\s*'
        r'actor_oper_port_state\s*'
        r'lacp_activity:(?P<a_lacp_activity>\S+) time_out:(?P<a_time_out>' +
        '\S+) aggregation:(?P<a_aggregation>\S+) sync:(?P<a_sync>\S+) ' +
        'collecting:(?P<a_collecting>\S+) distributing:(?P<a_distributing>' +
        '\S+) defaulted:(?P<a_defaulted>\S+) expired:(?P<a_expired>\S+)\s+'
        r'partner_oper_port_state\s*'
        r'lacp_activity:(?P<p_lacp_activity>\S+) time_out:(?P<p_time_out>' +
        '\S+) aggregation:(?P<p_aggregation>\S+) sync:(?P<p_sync>\S+) ' +
        'collecting:(?P<p_collecting>\S+) distributing:(?P<p_distributing>' +
        '\S+) defaulted:(?P<p_defaulted>\S+) expired:(?P<p_expired>\S+)\s+'
        r'lacp_control\s*'
        r'begin:(?P<begin>\S+) actor_churn:(?P<actor_churn>\S+) ' +
        'partner_churn:(?P<partner_churn>\S+) ready_n:(?P<ready_n>\S+) ' +
        'selected:(?P<selected>\S+) port_moved:(?P<port_moved>\S+) ' +
        'ntt:(?P<ntt>\S+) port_enabled:(?P<port_enabled>\S+)\s'
    )
    actor_data_keys = ['a_lacp_activity', 'a_time_out', 'a_aggregation',
                       'a_sync', 'a_collecting', 'a_distributing',
                       'a_defaulted', 'a_expired']
    partner_data_keys = ['p_lacp_activity', 'p_time_out', 'p_aggregation',
                         'p_sync', 'p_collecting', 'p_distributing',
                         'p_defaulted', 'p_expired']
    lacp_control_keys = ['begin', 'actor_churn', 'partner_churn', 'ready_n',
                         'selected', 'port_moved', 'ntt', 'port_enabled']
    result = {}
    actor_dict = {}
    partner_dict = {}
    lacp_control_dict = {}
    interface_data_dict = {}
    interface_dict = {}

    lag_block = raw_result.split('LAG lag')
    for block in lag_block:
        lag_id = block.split(':\n')[0]
        if lag_id:
            for re_partial in re.finditer(getlacpstate_actor_re, block):
                interface_data = re_partial.groupdict()
                for key, value in interface_data.items():
                    if value.isdigit():
                        interface_data[key] = int(value)
                for key_actor, key_partner, key_lacp_control in\
                        zip(actor_data_keys, partner_data_keys,
                            lacp_control_keys):
                        actor_dict[key_actor[2:]] = interface_data[key_actor]
                        partner_dict[key_partner[2:]] =\
                            interface_data[key_partner]
                        lacp_control_dict[key_lacp_control] =\
                            interface_data[key_lacp_control]
                interface_data_dict['actor_oper_port_state'] = actor_dict
                interface_data_dict['partner_oper_port_state'] = partner_dict
                interface_data_dict['lacp_control'] = lacp_control_dict
                actor_dict = {}
                partner_dict = {}
                lacp_control_dict = {}
                interface_dict[interface_data['interface']] =\
                    interface_data_dict
                interface_data_dict = {}
            result[lag_id] = interface_dict
            interface_dict = {}
    return result


def parse_diag_dump_lacp_basic_interfaces(raw_result):
    """
    Parse the 'diag-dump lacp basic' command raw output related to LACP
    interfaces.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the getlacpinterfaces in a dictionary of the
             form:

     ::

         {
            'lag':
                {'configured_members': [1, 2],
                 'eligible_members': [1, 2],
                 'participant_members': [1, 2],
                }
        }
    """

    getlacpcounters_re = (
        r'Port lag(?P<lag_number>\d+):\s*'
        r'configured_members\s+:[ ]?(?P<configured_interfaces>[\w \-]*)\s*'
        r'eligible_members\s+:[ ]?(?P<eligible_interfaces>[\w \-]*)\s*'
        r'participant_members\s+:[ ]?(?P<participant_interfaces>[\w \-]*)\s*'
    )
    result = {}

    for re_partial in re.finditer(getlacpcounters_re, raw_result):
        lag = re_partial.groupdict()
        lag_id = lag['lag_number']
        del lag['lag_number']
        lag['configured_interfaces'] = lag['configured_interfaces'].split()
        lag['eligible_interfaces'] = lag['eligible_interfaces'].split()
        lag['participant_interfaces'] = lag['participant_interfaces'].split()
        result[lag_id] = lag
    return result


def parse_show_snmpv3_users(raw_result):
    """
    Parse the 'show snmpv3 users' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show snmpv3 users\
       command in a dictionary of the form

    ::

        {
            'user1':{'AuthMode':'md5',
                       'PrivMode':'des'
            },
            'user2':{'AuthMode':'md5',
                       'PrivMode':'(null)'
            },
            'user3':{'AuthMode':'none',
                       'PrivMode':'none'
            }
        }
    """
    pattern_found = 0
    result = []
    output = {}
    res = 0
    for line in raw_result.splitlines():
        if pattern_found == 2:
            result.append(line)
        else:
            res = re.match(r'\s*-+\s*', line)
            if res:
                pattern_found = pattern_found + 1
    for line in result:
        res = re.split(r'\s+', line)
        output[res[0]] = {'AuthMode': res[1], 'PrivMode': res[2]}
    if output == {}:
        return None
    else:
        return output


def parse_show_snmp_agent_port(raw_result):
    """
    Parse the 'show snmp agent-port' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show snmp agent-port

    ::

        {
            'SNMP agent port': '677'
        }

    """

    print("In Parser method")
    snmp_agent_port_re = (
        r'\s*SNMP\s*agent\sport\s*:\s*(?P<agent_port>.+)'
    )

    re_result = re.match(snmp_agent_port_re, raw_result)
    print(re_result)

    if re_result is None:
        return re_result

    result = re_result.groupdict()
    print(result)

    return result


def parse_show_events(raw_result):
    """
    Parse the 'show events' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the 'show events' command \
        in a dictionary of the form:

     ::

         [
             {
                 'date': '2016-04-21:22:03:07.096457',
                 'daemon': 'ops-lacpd',
                 'severity': 'LOG_INFO',
                 'event_id': '15007',
                 'message': 'LACP system ID set to 70:72:cf:99:69:2f'
             },
             {
                 'date': '2016-04-26:21:38:20.359365',
                 'daemon': 'ops-lldpd',
                 'severity': 'LOG_INFO',
                 'event_id': '1002',
                 'message': 'LLDP Disabled'
             }
         ]

    """

    show_re = r'(?P<date>\S+)\|(?P<daemon>\S+)\|(?P<event_id>\S+)'\
        '\|(?P<severity>\S+)\|(?P<message>[\s*\S+]+)'

    result = []
    for curr_log in raw_result.splitlines():
        re_result = re.match(show_re, curr_log)
        if re_result:
            curr_res = re_result.groupdict()
            result.append(curr_res)

    return result


def parse_diag_dump(raw_result):
    """
    Parse the 'diag-dump' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the diag-dump command \
        in a dictionary of the form:

     ::

        {
            'result': 0
        }
    """

    diag_dump_re = (
        r'(Diagnostic dump captured for feature)'
    )

    result = {}
    for line in raw_result.splitlines():
        re_result = re.search(diag_dump_re, line)
        if re_result:
            result['result'] = 0
            break
        else:
            result['result'] = 1
    return result


__all__ = [
    'parse_show_vlan', 'parse_show_lacp_aggregates',
    'parse_show_lacp_interface', 'parse_show_interface',
    'parse_show_interface_mgmt', 'parse_show_interface_subinterface',
    'parse_show_lacp_configuration', 'parse_show_lldp_neighbor_info',
    'parse_show_lldp_statistics', 'parse_show_ip_bgp_summary',
    'parse_show_ip_bgp_neighbors', 'parse_show_ip_bgp',
    'parse_show_udld_interface', 'parse_ping_repetitions',
    'parse_ping6_repetitions', 'parse_show_rib',
    'parse_show_running_config', 'parse_show_ip_route',
    'parse_show_ipv6_route', 'parse_show_ipv6_bgp',
    'parse_show_ip_ecmp', 'parse_show_interface_loopback',
    'parse_show_ntp_associations', 'parse_show_ntp_authentication_key',
    'parse_show_ntp_statistics', 'parse_show_ntp_status',
    'parse_show_ntp_trusted_keys', 'parse_show_sflow',
    'parse_show_dhcp_server_leases', 'parse_show_dhcp_server',
    'parse_show_sflow_interface', 'parse_show_sftp_server',
    'parse_show_vlog_config', 'parse_show_vlog_config_feature',
    'parse_show_vlog_config_daemon', 'parse_show_vlog_config_list',
    'parse_show_vlog_daemon', 'parse_show_vlog_severity',
    'parse_show_vlog_daemon_severity', 'parse_show_vlog_severity_daemon',
    'parse_ping', 'parse_ping6',
    'parse_traceroute', 'parse_traceroute6',
    'parse_show_vlog', 'parse_show_interface_loopback_brief',
    'parse_show_ip_ospf_neighbor_detail', 'parse_show_ip_ospf_interface',
    'parse_show_ip_ospf', 'parse_show_ip_ospf_neighbor',
    'parse_show_startup_config',
    'parse_show_mac_address_table',
    'parse_show_tftp_server', 'parse_show_core_dump',
    'parse_config_tftp_server_enable',
    'parse_config_tftp_server_no_enable', 'parse_config_tftp_server_path',
    'parse_config_tftp_server_no_path', 'parse_show_interface_lag',
    'parse_show_mirror',
    'parse_config_tftp_server_no_path', 'parse_show_snmp_community',
    'parse_show_snmp_system', 'parse_show_snmp_trap',
    'parse_diag_dump_lacp_basic', 'parse_show_snmpv3_users',
    'parse_show_snmp_agent_port', 'parse_diag_dump', 'parse_show_events'
]
