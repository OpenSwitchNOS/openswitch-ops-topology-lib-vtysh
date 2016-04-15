# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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
OpenSwitch Test for vtysh related commands.
"""

from __future__ import unicode_literals
from deepdiff import DeepDiff

from topology_lib_vtysh.parser import (parse_show_interface,
                                       parse_show_interface_subinterface,
                                       parse_show_vlan,
                                       parse_show_lacp_interface,
                                       parse_show_lacp_aggregates,
                                       parse_show_lacp_configuration,
                                       parse_show_lldp_neighbor_info,
                                       parse_show_lldp_statistics,
                                       parse_show_ip_bgp_summary,
                                       parse_show_ip_bgp_neighbors,
                                       parse_show_ip_bgp,
                                       parse_show_ipv6_bgp,
                                       parse_show_ip_route,
                                       parse_show_ipv6_route,
                                       parse_show_rib,
                                       parse_ping_repetitions,
                                       parse_ping6_repetitions,
                                       parse_ping,
                                       parse_ping6,
                                       parse_traceroute,
                                       parse_traceroute6,
                                       parse_show_running_config,
                                       parse_show_ip_ecmp,
                                       parse_show_ntp_associations,
                                       parse_show_ntp_authentication_key,
                                       parse_show_ntp_statistics,
                                       parse_show_ntp_status,
                                       parse_show_ntp_trusted_keys,
                                       parse_show_dhcp_server_leases,
                                       parse_show_dhcp_server,
                                       parse_show_sflow,
                                       parse_show_sflow_interface,
                                       parse_show_sftp_server,
                                       parse_show_interface_loopback,
                                       parse_show_vlog_config,
                                       parse_show_vlog_config_feature,
                                       parse_show_vlog_config_daemon,
                                       parse_show_vlog_config_list,
                                       parse_show_vlog_daemon,
                                       parse_show_vlog_severity,
                                       parse_show_vlog_daemon_severity,
                                       parse_show_vlog_severity_daemon,
                                       parse_show_vlog,
                                       parse_show_ip_ospf_neighbor_detail,
                                       parse_show_ip_ospf_neighbor,
                                       parse_show_ip_ospf,
                                       parse_show_ip_ospf_interface,
                                       parse_show_startup_config,
                                       parse_show_mac_address_table,
                                       parse_show_tftp_server,
                                       parse_config_tftp_server_enable,
                                       parse_config_tftp_server_no_enable,
                                       parse_config_tftp_server_path,
                                       parse_config_tftp_server_no_path,
                                       parse_show_interface_lag,
                                       parse_show_mirror
                                       )


def test_parse_show_tftp_server():
    raw_result = """\
TFTP server configuration
-------------------------
TFTP server : Enabled
TFTP server secure mode : Disabled
TFTP server file path : /etc/ssl/certs/
    """

    result = parse_show_tftp_server(raw_result)
    print(result)
    expected = {
        'tftp_server': True,
        'tftp_server_secure_mode': False,
        'tftp_server_file_path': '/etc/ssl/certs/'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_config_tftp_server_enable():
    raw_result = """\
TFTP server is enabled successfully
    """

    result = parse_config_tftp_server_enable(raw_result)

    expected = {
        'result': True
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_config_tftp_server_no_enable():
    raw_result = """\
TFTP server is disabled successfully
    """

    result = parse_config_tftp_server_no_enable(raw_result)

    expected = {
        'result': True
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_config_tftp_server_path():
    raw_result = """\
TFTP server path is added successfully
    """

    result = parse_config_tftp_server_path(raw_result)

    expected = {
        'result': True
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_config_tftp_server_no_path():
    raw_result = """\
TFTP server path is deleted successfully
    """

    result = parse_config_tftp_server_no_path(raw_result)

    expected = {
        'result': True
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlan():
    raw_result = """\

--------------------------------------------------------------------------------
VLAN    Name      Status   Reason         Reserved       Ports
--------------------------------------------------------------------------------
2       vlan2     up       ok                            7, 3, 8, vlan2, 1
1       vlan1     down     admin_down
    """

    result = parse_show_vlan(raw_result)

    expected = {
        '1': {
            'name': 'vlan1',
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
VLAN 9 has not been configured
    """
    result = parse_show_vlan(raw_result)
    assert result is None


def test_parse_show_mac_address_table():
    raw_result = """\

MAC age-time            : 300 seconds
Number of MAC addresses : 2

MAC Address          VLAN     Type       Port
--------------------------------------------------
:00:00:00:00:00:01   1        dynamic    1
:00:00:00:00:00:02   2        dynamic    2
    """

    result = parse_show_mac_address_table(raw_result)

    expected = {
        'age_time': '300',
        'no_mac_address': '2',
        ':00:00:00:00:00:01': {
            'vlan_id': '1',
            'from': 'dynamic',
            'port': '1'
        },
        ':00:00:00:00:00:02': {
            'vlan_id': '2',
            'from': 'dynamic',
            'port': '2'
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
No MAC entries found
    """
    result = parse_show_mac_address_table(raw_result)
    assert not result


def test_parse_show_interface():
    raw_result = """\

Interface 7 is down (Administratively down)
 Admin state is down
 State information: admin_down
 Hardware: Ethernet, MAC Address: 70:72:cf:d7:d3:dd
 MTU 0
 Half-duplex
 Speed 0 Mb/s
 Auto-Negotiation is turned on
 Input flow-control is off, output flow-control is off
 RX
            0 input packets              0 bytes
            0 input error                0 dropped
            0 CRC/FCS
 TX
            0 output packets             0 bytes
            0 input error                0 dropped
            0 collision

    """

    result = parse_show_interface(raw_result)

    expected = {
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
        'rx_l3_ucast_packets': None,
        'rx_l3_ucast_bytes': None,
        'rx_l3_mcast_packets': None,
        'rx_l3_mcast_bytes': None,
        'speed': 0,
        'speed_unit': 'Mb/s',
        'state_description': 'Administratively down',
        'state_information': 'admin_down',
        'tx_bytes': 0,
        'tx_collisions': 0,
        'tx_dropped': 0,
        'tx_errors': 0,
        'tx_packets': 0,
        'tx_l3_ucast_packets': None,
        'tx_l3_ucast_bytes': None,
        'tx_l3_mcast_packets': None,
        'tx_l3_mcast_bytes': None,
        'ipv4': None,
        'ipv6': None
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result2 = """\

Interface 1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv4 address 20.1.1.2/30
 MTU 0
 Full-duplex
 Speed 1000 Mb/s
 Auto-Negotiation is turned on
 Input flow-control is off, output flow-control is off
 RX
            0 input packets              0 bytes
            0 input error                0 dropped
            0 CRC/FCS
 TX
            0 output packets             0 bytes
            0 input error                0 dropped
            0 collision
    """

    result2 = parse_show_interface(raw_result2)

    expected2 = {
        'admin_state': 'up',
        'autonegotiation': True,
        'conection_type': 'Full-duplex',
        'hardware': 'Ethernet',
        'input_flow_control': False,
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'output_flow_control': False,
        'port': 1,
        'rx_crc_fcs': 0,
        'rx_dropped': 0,
        'rx_bytes': 0,
        'rx_error': 0,
        'rx_packets': 0,
        'rx_l3_ucast_packets': None,
        'rx_l3_ucast_bytes': None,
        'rx_l3_mcast_packets': None,
        'rx_l3_mcast_bytes': None,
        'speed': 1000,
        'speed_unit': 'Mb/s',
        'state_description': None,
        'state_information': None,
        'tx_bytes': 0,
        'tx_collisions': 0,
        'tx_dropped': 0,
        'tx_errors': 0,
        'tx_packets': 0,
        'tx_l3_ucast_packets': None,
        'tx_l3_ucast_bytes': None,
        'tx_l3_mcast_packets': None,
        'tx_l3_mcast_bytes': None,
        'ipv4': '20.1.1.2/30',
        'ipv6': None
    }

    ddiff2 = DeepDiff(result2, expected2)
    assert not ddiff2

    raw_result3 = """\

Interface 1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv6 address 2002::1/64
 MTU 0
 Full-duplex
 Speed 1000 Mb/s
 Auto-Negotiation is turned on
 Input flow-control is off, output flow-control is off
 RX
            0 input packets              0 bytes
            0 input error                0 dropped
            0 CRC/FCS
 TX
            0 output packets             0 bytes
            0 input error                0 dropped
            0 collision
    """

    result3 = parse_show_interface(raw_result3)

    expected3 = {
        'admin_state': 'up',
        'autonegotiation': True,
        'conection_type': 'Full-duplex',
        'hardware': 'Ethernet',
        'input_flow_control': False,
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'output_flow_control': False,
        'port': 1,
        'rx_crc_fcs': 0,
        'rx_dropped': 0,
        'rx_bytes': 0,
        'rx_error': 0,
        'rx_packets': 0,
        'rx_l3_ucast_packets': None,
        'rx_l3_ucast_bytes': None,
        'rx_l3_mcast_packets': None,
        'rx_l3_mcast_bytes': None,
        'speed': 1000,
        'speed_unit': 'Mb/s',
        'state_description': None,
        'state_information': None,
        'tx_bytes': 0,
        'tx_collisions': 0,
        'tx_dropped': 0,
        'tx_errors': 0,
        'tx_packets': 0,
        'tx_l3_ucast_packets': None,
        'tx_l3_ucast_bytes': None,
        'tx_l3_mcast_packets': None,
        'tx_l3_mcast_bytes': None,
        'ipv4': None,
        'ipv6': '2002::1/64'
    }

    ddiff3 = DeepDiff(result3, expected3)
    assert not ddiff3

    raw_result4 = """\

Interface 1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv6 address 2002::1/64
 MTU 0
 Full-duplex
 Speed 1000 Mb/s
 Auto-Negotiation is turned on
 Input flow-control is off, output flow-control is off
 RX
            0 input packets              0 bytes
            0 input error                0 dropped
            0 CRC/FCS
       L3:
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
 TX
            0 output packets             0 bytes
            0 input error                0 dropped
            0 collision
       L3:
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
    """

    result4 = parse_show_interface(raw_result4)

    expected4 = {
        'admin_state': 'up',
        'autonegotiation': True,
        'conection_type': 'Full-duplex',
        'hardware': 'Ethernet',
        'input_flow_control': False,
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'output_flow_control': False,
        'port': 1,
        'rx_crc_fcs': 0,
        'rx_dropped': 0,
        'rx_bytes': 0,
        'rx_error': 0,
        'rx_packets': 0,
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 0,
        'rx_l3_mcast_bytes': 0,
        'speed': 1000,
        'speed_unit': 'Mb/s',
        'state_description': None,
        'state_information': None,
        'tx_bytes': 0,
        'tx_collisions': 0,
        'tx_dropped': 0,
        'tx_errors': 0,
        'tx_packets': 0,
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 0,
        'tx_l3_mcast_bytes': 0,
        'ipv4': None,
        'ipv6': '2002::1/64'
    }

    ddiff4 = DeepDiff(result4, expected4)
    assert not ddiff4


def test_parse_show_interface_subinterface():
    raw_result = """\
Interface 2.2 is up.
(Administratively down)
 Admin state is down
 Parent interface is 2
 Encapsulation dot1Q 102
 Hardware: Ethernet, MAC Address: 48:0f:cf:af:f1:cd
 IPv4 address 12.0.0.1/24
 Input flow-control is off, output flow-control is off
 RX
       L3:
            ucast: 233 packets, 3434 bytes
            mcast: 0 packets, 0 bytes
 TX
       L3:
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes

Interface 2.1 is up.

 Admin state is down
 Parent interface is 2
 Encapsulation dot1Q 101
 Hardware: Ethernet, MAC Address: 48:0f:cf:af:f1:cd
 IPv4 address 11.0.0.1/24
 Input flow-control is on, output flow-control is off
 RX
       L3:
            ucast: 34 packets, 544 bytes
            mcast: 54 packets, 345 bytes
 TX
       L3:
            ucast: 232 packets, 434434 bytes
            mcast: 23 packets, 2344 bytes

Interface 2.3 is up.
(Administratively down)
 Admin state is down
 Parent interface is 2
 Encapsulation dot1Q 103
 Hardware: Ethernet, MAC Address: 48:0f:cf:af:f1:cd
 IPv4 address 13.0.0.1/24
 Input flow-control is off, output flow-control is off
 RX
       L3:
            ucast: 555 packets, 234234 bytes
            mcast: 342 packets, 23432 bytes
 TX
       L3:
            ucast: 4433 packets, 2342342 bytes
            mcast: 545555 packets, 334234232 bytes

"""
    result = parse_show_interface_subinterface(raw_result)

    expected = {
        2: {'admin_state': 'down',
            'encapsulation_dot1q': 102,
            'hardware': 'Ethernet',
            'input_flow_control': False,
            'interface_state': 'up',
            'mac_address': '48:0f:cf:af:f1:cd',
            'output_flow_control': False,
            'parent_interface': 2,
            'port': 2,
            'rx_mcast_packets': 0,
            'rx_mcast_bytes': 0,
            'rx_ucast_packets': 233,
            'rx_ucast_bytes': 3434,
            'state_description': 'Administratively down',
            'state_information': None,
            'subinterface': 2,
            'tx_mcast_packets': 0,
            'tx_mcast_bytes': 0,
            'tx_ucast_packets': 0,
            'tx_ucast_bytes': 0,
            'ipv6': None,
            'ipv4': '12.0.0.1/24'},
        1: {'admin_state': 'down',
            'encapsulation_dot1q': 101,
            'hardware': 'Ethernet',
            'input_flow_control': True,
            'interface_state': 'up',
            'mac_address': '48:0f:cf:af:f1:cd',
            'output_flow_control': False,
            'parent_interface': 2,
            'port': 2,
            'rx_mcast_packets': 54,
            'rx_mcast_bytes': 345,
            'rx_ucast_packets': 34,
            'rx_ucast_bytes': 544,
            'state_description': None,
            'state_information': None,
            'subinterface': 1,
            'tx_mcast_packets': 23,
            'tx_mcast_bytes': 2344,
            'tx_ucast_packets': 232,
            'tx_ucast_bytes': 434434,
            'ipv6': None,
            'ipv4': '11.0.0.1/24'},
        3: {'admin_state': 'down',
            'encapsulation_dot1q': 103,
            'hardware': 'Ethernet',
            'input_flow_control': False,
            'interface_state': 'up',
            'mac_address': '48:0f:cf:af:f1:cd',
            'output_flow_control': False,
            'parent_interface': 2,
            'port': 2,
            'rx_mcast_packets': 342,
            'rx_mcast_bytes': 23432,
            'rx_ucast_packets': 555,
            'rx_ucast_bytes': 234234,
            'state_description': 'Administratively down',
            'state_information': None,
            'subinterface': 3,
            'tx_mcast_packets': 545555,
            'tx_mcast_bytes': 334234232,
            'tx_ucast_packets': 4433,
            'tx_ucast_bytes': 2342342,
            'ipv6': None,
            'ipv4': '13.0.0.1/24'}
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_interface_lag():
    raw_result = """\

Aggregate-name lag1
 Aggregated-interfaces : 2 1
 Aggregation-key : 1
 IPv4 address 10.1.1.1/24
 IPv4 address 10.1.1.2/24 secondary
 IPv6 address 2001::1/12
 IPv6 address 2001::2/12 secondary
 Speed 0 Mb/s
 RX
            0 input packets              0 bytes
            0 input error                0 dropped
            0 CRC/FCS
 TX
            0 output packets             0 bytes
            0 input error                0 dropped
            0 collision
"""

    result = parse_show_interface_lag(raw_result)

    expected = {
        'lag_name': 'lag1',
        'aggregated_interfaces': '2 1',
        'agg_key': 1,
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_lacp_interface():
    raw_result = """\
State abbreviations :
A - Active        P - Passive      F - Aggregable I - Individual
S - Short-timeout L - Long-timeout N - InSync     O - OutofSync
C - Collecting    D - Distributing
X - State m/c expired              E - Default neighbor state


Aggregate-name : lag100
-------------------------------------------------
                       Actor             Partner
-------------------------------------------------
Port-id            | 17                 | 0
Port-priority      | 1                  | 0
Key                | 100                | 0
State              | ALFOE              | PLFO
System-id          | 70:72:cf:52:54:84  | 00:00:00:00:00:00
System-priority    | 65534              | 0
"""

    result = parse_show_lacp_interface(raw_result)

    expected = {
        'lag_id': '100',
        'local_port_id': '17',
        'remote_port_id': '0',
        'local_port_priority': '1',
        'remote_port_priority': '0',
        'local_key': '100',
        'remote_key': '0',
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_lacp_aggregates():
    raw_result = """\
Aggregate-name        : lag1
Aggregated-interfaces : 4 9
Heartbeat rate        : slow
Fallback              : false
Hash                  : l3-src-dst
Aggregate mode        : off


Aggregate-name        : lag2
Aggregated-interfaces :
Heartbeat rate        : slow
Fallback              : false
Hash                  : l4-src-dst
Aggregate mode        : off
    """

    result = parse_show_lacp_aggregates(raw_result)

    expected = {
        'lag1': {
            'name': 'lag1',
            'interfaces': ['4', '9'],
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
            'hash': 'l4-src-dst',
            'mode': 'off'
        },
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_lacp_configuration():
    raw_result = """\
System-id       : 70:72:cf:af:66:e7
System-priority : 65534
    """

    result = parse_show_lacp_configuration(raw_result)

    expected = {
        'id': '70:72:cf:af:66:e7',
        'priority': 65534
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_lldp_neighbor_info():
    raw_result = """\
Port                           : 1
Neighbor entries               : 0
Neighbor entries deleted       : 0
Neighbor entries dropped       : 0
Neighbor entries age-out       : 0
Neighbor Chassis-Name          :
Neighbor Chassis-Description   :
Neighbor Chassis-ID            :
Neighbor Management-Address    :
Chassis Capabilities Available :
Chassis Capabilities Enabled   :
Neighbor Port-ID               :
TTL                            :
    """

    result = parse_show_lldp_neighbor_info(raw_result)

    expected = {
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
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_lldp_statistics():
    raw_result = """\
Total Packets transmitted : 0
Total Packets received : 0
Total Packet received and discarded : 0
Total TLVs unrecognized : 0
    """

    result = parse_show_lldp_statistics(raw_result)

    expected = {
        'total_packets_transmited': 0,
        'total_packets_received': 0,
        'total_packets_received_and_discarded': 0,
        'total_tlvs_unrecognized': 0
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_sftp_server():
    raw_result = """\
SFTP server configuration
-------------------------
SFTP server : Enabled
"""

    result = parse_show_sftp_server(raw_result)

    expected = {
        'status': 'Enabled',
        'ServerName': 'SFTP server'
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_bgp_summary():
    raw_result = """\
BGP router identifier 2.0.0.1, local AS number 64000
RIB entries 5
Peers 3

Neighbor             AS MsgRcvd MsgSent Up/Down  State
192.168.1.10      64000       0       0 never           Idle
20.1.1.1          65000       0       0 never         Active
20.1.1.10         65000       0       0 never         Active
    """

    result = parse_show_ip_bgp_summary(raw_result)

    expected = {
        'bgp_router_identifier': '2.0.0.1',
        '20.1.1.1': {
            'up_down': 'never',
            'state': 'Active',
            'msgsent': 0,
            'neighbor': '20.1.1.1',
            'as_number': 65000,
            'msgrcvd': 0
        },
        'rib_entries': 5,
        'peers': 3,
        '192.168.1.10': {
            'up_down': 'never',
            'state': 'Idle',
            'msgsent': 0,
            'neighbor': '192.168.1.10',
            'as_number': 64000,
            'msgrcvd': 0
        },
        '20.1.1.10': {
            'up_down': 'never',
            'state': 'Active',
            'msgsent': 0,
            'neighbor': '20.1.1.10',
            'as_number': 65000,
            'msgrcvd': 0
        },
        'local_as_number': 64000
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ipv6_bgp():
    raw_result = """\
Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
              i internal, S Stale, R Removed
Origin codes: i - IGP, e - EGP, ? - incomplete

Local router-id 1.1.1.2
   Network          Next Hop            Metric LocPrf Weight Path
*> 10::/126         3::1                     0      0      0 65001 i
*> 10::10/126       ::                       0      0      0 65001 i
*> 10::14/126       ::                       0      0      0 65001 i
*> 10::18/126       ::                       0      0      0 65001 i
*> 10::1c/126       ::                       0      0      0 65001 i
*> 10::20/126       ::                       0      0      0 65001 i
*> 10::24/126       ::                       0      0      0 65001 i
*> 10::4/126        ::                       0      0      0 65001 i
*> 10::8/126        ::                       0      0      0 65001 i
*> 10::c/126        ::                       0      0      0 65001 i
Total number of entries 10
    """

    result = parse_show_ipv6_bgp(raw_result)

    expected = [
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::/126',
            'locprf': 0,
            'next_hop': '3::1',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::10/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::14/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::18/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::1c/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::20/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::24/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::4/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::8/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        },
        {
            'path': '65001 i',
            'metric': 0,
            'weight': 0,
            'network': '10::c/126',
            'locprf': 0,
            'next_hop': '::',
            'route_status': '*>'
        }
    ]

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_bgp_neighbors():
    raw_result = """\
  name: 192.168.1.10, remote-as: 64000
    state: Active
    tcp_port_number: 179

    statistics:
       bgp_peer_dropped_count: 0
       bgp_peer_dynamic_cap_in_count: 0
       bgp_peer_dynamic_cap_out_count: 0
       bgp_peer_established_count: 0
       bgp_peer_keepalive_in_count: 0
       bgp_peer_keepalive_out_count: 0
       bgp_peer_notify_in_count: 0
       bgp_peer_notify_out_count: 0
       bgp_peer_open_in_count: 0
       bgp_peer_open_out_count: 0
       bgp_peer_readtime: 611931
       bgp_peer_refresh_in_count: 0
       bgp_peer_refresh_out_count: 0
       bgp_peer_resettime: 611931
       bgp_peer_update_in_count: 0
       bgp_peer_update_out_count: 0
       bgp_peer_uptime: 0

  name: 20.1.1.1, remote-as: 65000
    state: Active
    tcp_port_number: 179

    statistics:
       bgp_peer_dropped_count: 0
       bgp_peer_dynamic_cap_in_count: 0
       bgp_peer_dynamic_cap_out_count: 0
       bgp_peer_established_count: 0
       bgp_peer_keepalive_in_count: 0
       bgp_peer_keepalive_out_count: 0
       bgp_peer_notify_in_count: 0
       bgp_peer_notify_out_count: 0
       bgp_peer_open_in_count: 0
       bgp_peer_open_out_count: 0
       bgp_peer_readtime: 611931
       bgp_peer_refresh_in_count: 0
       bgp_peer_refresh_out_count: 0
       bgp_peer_resettime: 611931
       bgp_peer_update_in_count: 0
       bgp_peer_update_out_count: 0
       bgp_peer_uptime: 0

  name: 20.1.1.10, remote-as: 65000
    state: Active
    tcp_port_number: 179

    statistics:
       bgp_peer_dropped_count: 0
       bgp_peer_dynamic_cap_in_count: 0
       bgp_peer_dynamic_cap_out_count: 0
       bgp_peer_established_count: 0
       bgp_peer_keepalive_in_count: 0
       bgp_peer_keepalive_out_count: 0
       bgp_peer_notify_in_count: 0
       bgp_peer_notify_out_count: 0
       bgp_peer_open_in_count: 0
       bgp_peer_open_out_count: 0
       bgp_peer_readtime: 611931
       bgp_peer_refresh_in_count: 0
       bgp_peer_refresh_out_count: 0
       bgp_peer_resettime: 611931
       bgp_peer_update_in_count: 0
       bgp_peer_update_out_count: 0
       bgp_peer_uptime: 0
    """

    result = parse_show_ip_bgp_neighbors(raw_result)

    expected = {
        '20.1.1.1': {
            'state': 'Active',
            'bgp_peer_keepalive_out_count': 0,
            'bgp_peer_readtime': 611931,
            'bgp_peer_uptime': 0,
            'tcp_port_number': 179,
            'bgp_peer_refresh_in_count': 0,
            'bgp_peer_notify_in_count': 0,
            'bgp_peer_keepalive_in_count': 0,
            'bgp_peer_resettime': 611931,
            'name': '20.1.1.1',
            'bgp_peer_update_out_count': 0,
            'bgp_peer_open_in_count': 0,
            'bgp_peer_open_out_count': 0,
            'bgp_peer_dynamic_cap_in_count': 0,
            'remote_as': 65000,
            'bgp_peer_established_count': 0,
            'bgp_peer_notify_out_count': 0,
            'bgp_peer_refresh_out_count': 0,
            'bgp_peer_dynamic_cap_out_count': 0,
            'bgp_peer_dropped_count': 0,
            'bgp_peer_update_in_count': 0
        },
        '20.1.1.10': {
            'state': 'Active',
            'bgp_peer_keepalive_out_count': 0,
            'bgp_peer_readtime': 611931,
            'bgp_peer_uptime': 0,
            'tcp_port_number': 179,
            'bgp_peer_refresh_in_count': 0,
            'bgp_peer_notify_in_count': 0,
            'bgp_peer_keepalive_in_count': 0,
            'bgp_peer_resettime': 611931,
            'name': '20.1.1.10',
            'bgp_peer_update_out_count': 0,
            'bgp_peer_open_in_count': 0,
            'bgp_peer_open_out_count': 0,
            'bgp_peer_dynamic_cap_in_count': 0,
            'remote_as': 65000,
            'bgp_peer_established_count': 0,
            'bgp_peer_notify_out_count': 0,
            'bgp_peer_refresh_out_count': 0,
            'bgp_peer_dynamic_cap_out_count': 0,
            'bgp_peer_dropped_count': 0,
            'bgp_peer_update_in_count': 0
        },
        '192.168.1.10': {
            'state': 'Active',
            'bgp_peer_keepalive_out_count': 0,
            'bgp_peer_readtime': 611931,
            'bgp_peer_uptime': 0,
            'tcp_port_number': 179,
            'bgp_peer_refresh_in_count': 0,
            'bgp_peer_notify_in_count': 0,
            'bgp_peer_keepalive_in_count': 0,
            'bgp_peer_resettime': 611931,
            'name': '192.168.1.10',
            'bgp_peer_update_out_count': 0,
            'bgp_peer_open_in_count': 0,
            'bgp_peer_open_out_count': 0,
            'bgp_peer_dynamic_cap_in_count': 0,
            'remote_as': 64000,
            'bgp_peer_established_count': 0,
            'bgp_peer_notify_out_count': 0,
            'bgp_peer_refresh_out_count': 0,
            'bgp_peer_dynamic_cap_out_count': 0,
            'bgp_peer_dropped_count': 0,
            'bgp_peer_update_in_count': 0
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_bgp():
    raw_result = """\
Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
              i internal, S Stale, R Removed
Origin codes: i - IGP, e - EGP, ? - incomplete

Local router-id 2.0.0.1
   Network          Next Hop            Metric LocPrf Weight Path
*> 10.1.0.10/32     0.0.0.0                  0      0  32768  i
*> 10.1.0.14/32     0.0.0.0                  0      0  32768  i
*> 10.2.0.10/32     20.1.1.1                 0      0      0 65000 64100 i
*  10.2.0.10/32     20.1.1.10                0      0      0 65000 64100 i
*> 10.2.0.14/32     20.1.1.1                 0      0      0 65000 64100 i
*  10.2.0.14/32     20.1.1.10                0      0      0 65000 64100 i
Total number of entries 6
    """

    result = parse_show_ip_bgp(raw_result)

    expected = [
        {
            'path': 'i',
            'metric': 0,
            'weight': 32768,
            'network': '10.1.0.10/32',
            'locprf': 0,
            'next_hop': '0.0.0.0',
            'route_status': '*>'
        },
        {
            'path': 'i',
            'metric': 0,
            'weight': 32768,
            'network': '10.1.0.14/32',
            'locprf': 0,
            'next_hop': '0.0.0.0',
            'route_status': '*>'
        },
        {
            'path': '65000 64100 i',
            'metric': 0,
            'weight': 0,
            'network': '10.2.0.10/32',
            'locprf': 0,
            'next_hop': '20.1.1.1',
            'route_status': '*>'
        },
        {
            'path': '65000 64100 i',
            'metric': 0,
            'weight': 0,
            'network': '10.2.0.10/32',
            'locprf': 0,
            'next_hop': '20.1.1.10',
            'route_status': '*'
        },
        {
            'path': '65000 64100 i',
            'metric': 0,
            'weight': 0,
            'network': '10.2.0.14/32',
            'locprf': 0,
            'next_hop': '20.1.1.1',
            'route_status': '*>'
        },
        {
            'path': '65000 64100 i',
            'metric': 0,
            'weight': 0,
            'network': '10.2.0.14/32',
            'locprf': 0,
            'next_hop': '20.1.1.10',
            'route_status': '*'
        }
    ]

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_ping_repetitions():
    raw_result = """\
PING 10.0.0.2 (10.0.0.2) 100(128) bytes of data.
108 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.213 ms

--- 10.0.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.213/0.213/0.213/0.000 ms
    """

    result = parse_ping_repetitions(raw_result)

    expected = {
        'transmitted': 1,
        'received': 1,
        'errors': 0,
        'packet_loss': 0
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_ping6_repetitions():
    raw_result = """\
PING 2000::2 (2000::2) 100(128) bytes of data.
108 bytes from 2000::2: icmp_seq=1 ttl=64 time=0.465 ms

--- 2000::2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.465/0.465/0.465/0.000 ms
    """

    result = parse_ping6_repetitions(raw_result)

    expected = {
        'transmitted': 1,
        'received': 1,
        'errors': 0,
        'packet_loss': 0
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_ping():
    raw_result = """\
    PATTERN: 0xabcd
    PING 10.1.1.1 (10.1.1.1) 100(128) bytes of data.
    108 bytes from 10.1.1.1: icmp_seq=1 ttl=64 time=0.037 ms
    108 bytes from 10.1.1.1: icmp_seq=2 ttl=64 time=0.028 ms

    --- 10.1.1.1 ping statistics ---
    2 packets transmitted, 2 received, 0% packet loss, time 999ms
    rtt min/avg/max/mdev = 0.028/0.032/0.037/0.007 ms
    """

    result = parse_ping(raw_result)

    expected = {
        'transmitted': 2,
        'received': 2,
        'errors': 'No match found',
        'loss_pc': 0,
        'datagram_size': 100,
        'time': 999,
        'data': 'abcd',
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_ping6():
    raw_result = """\
    PATTERN: 0xabcd
    PING 1001::1(1001::1) 100 data bytes
    108 bytes from 1001::1: icmp_seq=1 ttl=64 time=0.043 ms
    108 bytes from 1001::1: icmp_seq=2 ttl=64 time=0.071 ms

    --- 1001::1 ping statistics ---
    2 packets transmitted, 2 received, 0% packet loss, time 1000ms
    rtt min/avg/max/mdev = 0.043/0.057/0.071/0.014 ms
    """

    result = parse_ping6(raw_result)

    expected = {
        'transmitted': 2,
        'received': 2,
        'errors': 'No match found',
        'loss_pc': 0,
        'time': 1000,
        'datagram_size': 100,
        'data': 'abcd'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_traceroute():
    raw_result = """traceroute to 10.1.1.10 (10.1.1.10), 1 hops min, 30 hops max, 3 sec. timeout, 5 probes
    1   50.1.1.4  0.217ms  0.189ms  0.141ms 0.211ms  0.155ms
    2   40.1.1.3  0.216ms  0.144ms  0.222ms 0.211ms  0.155ms"""  # noqa

    result = parse_traceroute(raw_result)

    expected = {
        1: {
            'time_stamp2': '0.189',
            'time_stamp3': '0.141',
            'time_stamp1': '0.217',
            'time_stamp4': '0.211',
            'time_stamp5': '0.155',
            'int_hop': '50.1.1.4',
            'hop_num': 1
        },
        2: {
            'time_stamp2': '0.144',
            'time_stamp3': '0.222',
            'time_stamp4': '0.211',
            'time_stamp5': '0.155',
            'time_stamp1': '0.216',
            'hop_num': 2,
            'int_hop': '40.1.1.3'
        },
        'probe': 5,
        'min_ttl': 1,
        'dest_addr': '10.1.1.10',
        'max_ttl': 30,
        'time_out': 3
        }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_traceroute6():
    raw_result = """traceroute to 1001::10 (1001::10) from 5001::5, 200 hops max, 3 sec. timeout, 5 probes, 24 byte packets
    1  5001::4 (5001::4)  0.217 ms  0.189 ms  0.141 ms 0.211 ms  0.155 ms
    2  4001::3 (4001::3)  0.216 ms  0.144 ms  0.222 ms 0.211 ms  0.155 ms"""  # noqa

    result = parse_traceroute6(raw_result)

    expected = {
        1: {
            'time_stamp2': '0.189',
            'time_stamp3': '0.141',
            'time_stamp1': '0.217',
            'time_stamp4': '0.211',
            'time_stamp5': '0.155',
            'int_hop': '5001::4',
            'hop_num': 1
        },
        2: {
            'time_stamp2': '0.144',
            'time_stamp3': '0.222',
            'time_stamp4': '0.211',
            'time_stamp5': '0.155',
            'time_stamp1': '0.216',
            'hop_num': 2,
            'int_hop': '4001::3'
        },
        'dest_addr': '1001::10',
        'max_ttl': 200,
        'time_out': 3,
        'probe': 5,
        'source_addr': '5001::5'
        }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_rib():
    raw_result = """
Displaying ipv4 rib entries

'*' denotes selected
'[x/y]' denotes [distance/metric]

*140.0.0.0/30,  1 unicast next-hops
    *via  10.10.0.2,  [20/0],  BGP
*140.0.0.4/30,  1 unicast next-hops
    *via  10.10.0.2,  [20/0],  BGP
*193.0.0.2/32,  2 unicast next-hops
    *via  50.0.0.2,  [1/0],  static
    *via  56.0.0.3,  [1/0],  static
*10.10.0.0/24,  1 unicast next-hops
    *via  1,  [0/0],  connected

Displaying ipv6 rib entries

'*' denotes selected
'[x/y]' denotes [distance/metric]

*2002::/64,  1 unicast next-hops
    *via  4,  [0/0],  connected
*2010:bd9::/32,  3 unicast next-hops
    *via  2005::2,  [1/0],  static
    *via  2001::2,  [1/0],  static
    via  2002::2,  [1/0],  static
    """

    result = parse_show_rib(raw_result)

    expected = {
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
                'id': '140.0.0.4',
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """

No ipv4 rib entries

No ipv6 rib entries
    """

    result = parse_show_rib(raw_result)

    expected = {
        'ipv4_entries': [],
        'ipv6_entries': []
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_running_config():
    raw_result = """\
Current configuration:
!
!
!
!
!
router bgp 6400
     bgp router-id 7.7.7.7
     network 10.1.0.0/24
     network 10.1.1.0/24
     timers bgp 90 30
     neighbor 10.1.11.100 remote-as 11
     neighbor 10.1.12.100 remote-as 12
!
router ospf
    router-id 7.7.7.7
    network 10.1.11.100/24 area 10.1.0.0
    network 10.1.12.100/24 area 10.1.0.0
vlan 1
    no shutdown
vlan 8
    no shutdown
vlan 10
    no shutdown
vlan 11
    no shutdown
vlan 12
    no shutdown
interface vlan10
    no shutdown
    ip address 10.1.10.1/24
interface vlan12
    no shutdown
    ip address 10.1.12.1/24
interface vlan11
    no shutdown
    ip address 10.1.11.1/24
interface 1
    no shutdown
    no routing
    vlan access 8
interface 2
    no shutdown
    no routing
    vlan access 8
interface 7
    no shutdown
    ip address 100.1.1.100/24
interface 35
    no shutdown
    speed 1000
    mtu 1518
    flowcontrol receive on
    flowcontrol send on
    autonegotiation off
    lacp port-id 2
    lacp port-priority 3
    no routing
    vlan trunk native 8
    vlan trunk allowed 12
interface 50
    no shutdown
    mtu 1518
    flowcontrol receive on
    flowcontrol send on
    autonegotiation off
    no routing
    vlan trunk allowed 10
    vlan trunk allowed 11
    vlan trunk allowed 12
interface loopback 2
    ip address 10.0.0.1/24
    ipv6 address 2001::2/64
interface mgmt
    ip static 1.1.1.1/24
    nameserver 2.2.2.2
sftp-server
    enable
"""

    result = parse_show_running_config(raw_result)

    expected = {
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
                'ipv4': '10.0.0.1/24',
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
            }
        },
        'sftp-server': {
            'status': 'enable'
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_ecmp():
    raw_result = """\
ECMP Configuration
---------------------

ECMP Status        : Enabled
Resilient Hashing  : Disabled

ECMP Load Balancing by
------------------------
Source IP          : Enabled
Destination IP     : Disabled
Source Port        : Enabled
Destination Port   : Disabled
"""
    result = parse_show_ip_ecmp(raw_result)

    expected = {
        'global_status': True,
        'resilient': False,
        'src_ip': True,
        'dest_ip': False,
        'src_port': True,
        'dest_port': False
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_route():
    raw_result = """
Displaying ipv4 routes selected for forwarding

'[x/y]' denotes [distance/metric]

140.0.0.0/30,  1 unicast next-hops
    via  10.10.0.2,  [20/0],  bgp
140.0.0.4/30,  1 unicast next-hops
    via  10.10.0.2,  [20/0],  bgp
10.10.0.0/24,  1 unicast next-hops
    via  1,  [0/0],  connected
193.0.0.2/32,  2 unicast next-hops
    via  50.0.0.2,  [1/0],  static
    via  56.0.0.3,  [1/0],  static
    """

    result = parse_show_ip_route(raw_result)

    expected = [
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
            'id': '140.0.0.4',
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ipv6_route():
    raw_result = """
Displaying ipv6 routes selected for forwarding

'[x/y]' denotes [distance/metric]

2002::/64,  1 unicast next-hops
        via  1,  [0/0],  connected
2003::/64,  2 unicast next-hops
        via  2004::2000:0:0:2,  [1/0],  static
        via  2004::4000:0:0:2,  [1/0],  static
2004::2000:0:0:0/67,  1 unicast next-hops
        via  2,  [0/0],  connected
    """

    result = parse_show_ipv6_route(raw_result)

    expected = [
        {
            'id': '2002::/64',
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
            'id': '2003::/64',
            'next_hops': [
                {
                    'via': '2004::2000:0:0:2',
                    'distance': '1',
                    'from': 'static',
                    'metric': '0'
                },
                {
                    'via': '2004::4000:0:0:2',
                    'distance': '1',
                    'from': 'static',
                    'metric': '0'
                }
            ]
        },
        {
            'id': '2004::2000:0:0:0/67',
            'next_hops': [
                {
                    'via': '2',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                }
            ]
        },
    ]

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ntp_associations():
    raw_result = """\
--------------------------------------------------------------------------\
--------------------------------------------
ID             NAME           REMOTE  VER  KEYID           REF-ID  ST  T  \
LAST  POLL  REACH    DELAY  OFFSET  JITTER
--------------------------------------------------------------------------\
--------------------------------------------
   1    domain.com                -       3      -                -   -  -\
   -     -      -        -       -       -
*  2    192.168.1.100    192.168.1.100    3      10  172.16.135.123   4  U\
    41    64    377    0.138  17.811   1.942
   3    192.168.1.103    192.168.1.103    3      -           .STEP.  16  U\
   -  1024      0    0.000   0.000   0.000
--------------------------------------------------------------------------\
--------------------------------------------
    """

    result = parse_show_ntp_associations(raw_result)

    expected = {
        '1': {
            'code': ' ',
            'id': '1',
            'name': 'domain.com',
            'remote': '-',
            'version': '3',
            'key_id': '-',
            'reference_id': '-',
            'stratum': '-',
            'type': '-',
            'last': '-',
            'poll': '-',
            'reach': '-',
            'delay': '-',
            'offset': '-',
            'jitter': '-'
        },
        '2': {
            'code': '*',
            'id': '2',
            'name': '192.168.1.100',
            'remote': '192.168.1.100',
            'version': '3',
            'key_id': '10',
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
        '3': {
            'code': ' ',
            'id': '3',
            'name': '192.168.1.103',
            'remote': '192.168.1.103',
            'version': '3',
            'key_id': '-',
            'reference_id': '.STEP.',
            'stratum': '16',
            'type': 'U',
            'last': '-',
            'poll': '1024',
            'reach': '0',
            'delay': '0.000',
            'offset': '0.000',
            'jitter': '0.000'
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ntp_authentication_key():
    raw_result = """---------------------------
Auth-key       MD5 password
---------------------------
    10        MyPassword
    11        MyPassword_2
---------------------------
    """

    result = parse_show_ntp_authentication_key(raw_result)

    expected = {
        '10': {
            'key_id': '10',
            'md5_password': 'MyPassword'
        },
        '11': {
            'key_id': '11',
            'md5_password': 'MyPassword_2'
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ntp_statistics():
    raw_result = """             Rx-pkts    234793
     Cur Ver Rx-pkts    15
     Old Ver Rx-pkts    191
          Error pkts    16
    Auth-failed pkts    17
       Declined pkts    18
     Restricted pkts    19
   Rate-limited pkts    20
            KOD pkts    21
    """

    result = parse_show_ntp_statistics(raw_result)

    expected = {
        'rx_pkts': 234793,
        'cur_ver_rx_pkts': 15,
        'old_ver_rx_pkts': 191,
        'error_pkts': 16,
        'auth_failed_pkts': 17,
        'declined_pkts': 18,
        'restricted_pkts': 19,
        'rate_limited_pkts': 20,
        'kod_pkts': 21
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ntp_status():
    raw_result = """NTP is enabled
NTP authentication is disabled
Uptime: 592 second(s)
Synchronized to NTP Server 192.168.1.100 at stratum 5
Poll interval = 64 seconds
Time accuracy is within -0.829 seconds
Reference time: Mon Feb 15 2016 16:59:20.909 (UTC)
    """

    result = parse_show_ntp_status(raw_result)

    expected = {
        'status': 'enabled',
        'authentication_status': 'disabled',
        'uptime': 592,
        'server': '192.168.1.100',
        'stratum': '5',
        'poll_interval': '64',
        'time_accuracy': '-0.829',
        'reference_time': 'Mon Feb 15 2016 16:59:20.909 (UTC)'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ntp_status_not_synch():
    raw_result = """NTP is enabled
NTP authentication is disabled
Uptime: 2343 second(s)
    """

    result = parse_show_ntp_status(raw_result)

    expected = {
        'status': 'enabled',
        'authentication_status': 'disabled',
        'uptime': 2343
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ntp_trusted_keys():
    raw_result = """------------
Trusted-keys
------------
    10
    11
------------"""

    result = parse_show_ntp_trusted_keys(raw_result)

    expected = {
        '10': {'key_id': '10'},
        '11': {'key_id': '11'}
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_dhcp_server_leases():
    raw_result = """\
Expiry Time                MAC Address       IP Address  Hostname and Client-id
-------------------------------------------------------------------------------
Thu Mar  3 05:36:11 2016   00:50:56:b4:6c:36   192.168.10.10  cl02-win8   *
Wed Sep 23 23:07:12 2015   10:55:56:b4:6c:c6   192.168.20.10  95_h1       *
                """

    result = parse_show_dhcp_server_leases(raw_result)

    expected = {
        '192.168.10.10': {
            'expiry_time': 'Thu Mar  3 05:36:11 2016',
            'mac_address': '00:50:56:b4:6c:36',
            'ip_address': '192.168.10.10',
            'hostname': 'cl02-win8',
            'client_id': '*'
        },
        '192.168.20.10': {
            'expiry_time': 'Wed Sep 23 23:07:12 2015',
            'mac_address': '10:55:56:b4:6c:c6',
            'ip_address': '192.168.20.10',
            'hostname': '95_h1',
            'client_id': '*'
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_dhcp_server():
    raw_result = """\
DHCP dynamic IP allocation configuration
----------------------------------------
Name              Start IP Address                              End IP A\
ddress                                Netmask          Broadcast        \
Prefix-len  Lease time(min)  Static  Set tag          Match tags
------------------------------------------------------------------------\
------------------------------------------------------------------------\
----------------------------------------------------------------
CLIENTS-VLAN60    192.168.60.10                                 192.168.\
60.250                                255.255.255.0    192.168.60.255   \
*           1440             False   *                *


DHCP static IP allocation configuration
---------------------------------------
DHCP static host is not configured.


DHCP options configuration
--------------------------
Option Number  Option Name       Option Value          ipv6   Match tags
------------------------------------------------------------------------
15             *                 tigerlab.ntl.com      False  *
*              Router            192.168.60.254        False  *
6              *                 10.100.205.200        False  *


DHCP Match configuration
------------------------
DHCP match is not configured.


DHCP BOOTP configuration
------------------------
DHCP BOOTP is not configured.
    """

    result = parse_show_dhcp_server(raw_result)

    expected = {
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_sflow():
    raw_result = """\
sFlow Configuration
-----------------------------------------
sFlow                         enabled
Collector IP/Port/Vrf         10.10.11.2/6343/vrf_default
Agent Interface               2
Agent Address Family          ipv4
Sampling Rate                 20
Polling Interval              30
Header Size                   128
Max Datagram Size             1400
Number of Samples             10
    """

    result = parse_show_sflow(raw_result)

    expected = {
        'sflow': 'enabled',
        'collector': [
            {
                'ip': '10.10.11.2',
                'port': '6343',
                'vrf': 'vrf_default'
            }
        ],
        'agent_interface': '2',
        'agent_address_family': 'ipv4',
        'sampling_rate': 20,
        'polling_interval': 30,
        'header_size': 128,
        'max_datagram_size': 1400,
        'number_of_samples': 10
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
sFlow Configuration
-----------------------------------------
sFlow                         disabled
Collector IP/Port/Vrf         10.10.11.2/6344/vrf_mgmt
Agent Interface               Not set
Agent Address Family          ipv6
Sampling Rate                 20
Polling Interval              30
Header Size                   128
Max Datagram Size             1400
Number of Samples             20
    """

    result = parse_show_sflow(raw_result)

    expected = {
        'sflow': 'disabled',
        'collector': [
            {
                'ip': '10.10.11.2',
                'port': '6344',
                'vrf': 'vrf_mgmt'
            }
        ],
        'agent_interface': 'Not set',
        'agent_address_family': 'ipv6',
        'sampling_rate': 20,
        'polling_interval': 30,
        'header_size': 128,
        'max_datagram_size': 1400,
        'number_of_samples': 20
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_interface_loopback():
    raw_result = """
 Interface lo2 is up
 Admin state is up
 Hardware: Loopback
 IPv4 address 10.0.0.1/24
 IPv6 address 2001::2/64
     """

    result = parse_show_interface_loopback(raw_result)
    expected = {
        'lo2':
        {'AdminState': 'up',
         'ipv6_address': '2001::2/64',
         'ipv4_address': '10.0.0.1/24'}
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_sflow_interface():
    raw_result = """\
sFlow Configuration - Interface 1
-----------------------------------------
sFlow                         enabled
Sampling Rate                 20
Number of Samples             10
    """

    result = parse_show_sflow_interface(raw_result)

    expected = {
        'interface': 1,
        'sflow': 'enabled',
        'sampling_rate': 20,
        'number_of_samples': 10
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
sFlow Configuration - Interface 1
-----------------------------------------
sFlow                         disabled
Sampling Rate                 20
Number of Samples             20
    """

    result = parse_show_sflow_interface(raw_result)

    expected = {
        'interface': 1,
        'sflow': 'disabled',
        'sampling_rate': 20,
        'number_of_samples': 20
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_config():
    raw_result = """\
=================================================
Feature         Daemon          Syslog     File
=================================================
lldp            ops-lldpd       INFO       INFO

lacp            ops-lacpd       INFO       INFO

fand            ops-fand        INFO       INFO
    """

    result = parse_show_vlog_config(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_config_daemon():
    raw_result = """\
======================================
Daemon              Syslog     File
======================================
ops-lldpd           INFO       INFO
    """

    result = parse_show_vlog_config_daemon(raw_result)

    expected = False

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_config_feature():
    raw_result = """\
========================================
Feature               Syslog     File
========================================
lacp                  INFO       INFO
    """

    result = parse_show_vlog_config_feature(raw_result)

    expected = False

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_config_list():
    raw_result = """\
=============================================
Features          Description
=============================================
lldp              Link Layer Discovery
lacp              Link Aggregation Con
fand              System Fan
    """

    result = parse_show_vlog_config_list(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_daemon():
    raw_result = """\
---------------------------------------------------
show vlog
-----------------------------------------------------
ovs|00005|ops_ledd|INFO|ops-ledd (OpenSwitch ledd) 2.5.0
    """

    result = parse_show_vlog_daemon(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_severity():
    raw_result = """\
---------------------------------------------------
show vlog
-----------------------------------------------------
ovs-vswitchd-sim|ovs|00004|fatal_signal|WARN|terminating with signal 15\
(Terminated)

ovsdb-server|ovs|00002|fatal_signal|WARN|terminating with signal 15\
(Terminated)

ops-sysd|ovs|00005|ovsdb_if|ERR|Failed to commit the transaction. rc =7

ops-sysd|ovs|00006|ovsdb_if|ERR|Failed to commit the transaction. rc = 7

ops-pmd|ovs|00007|plug|WARN|Failed to read module disable register: 54 (2)

ops-pmd|ovs|00008|plug|WARN|Failed to read module disable register: 52 (2)
    .....
    """

    result = parse_show_vlog_severity(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_daemon_severity():
    raw_result = """\
---------------------------------------------------
show vlog
-----------------------------------------------------
ovs|00006|ops_portd|INFO|ops-portd (ops-portd) 2.5.0
    """

    result = parse_show_vlog_daemon_severity(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog_severity_daemon():
    raw_result = """\
---------------------------------------------------
show vlog
-----------------------------------------------------
ovs|00006|ops_portd|INFO|ops-portd (ops-portd) 2.5.0
    """

    result = parse_show_vlog_severity_daemon(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlog():
    raw_result = """\
%Unknown command
    """

    result = parse_show_vlog(raw_result)

    expected = True

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_ospf_interface():

    raw_result = """Interface 1 BW 1000 Mbps  <up,BROADCAST,up >
    Internet address 10.10.10.2/24 Area 0.0.0.1
    MTU mismatch detection: enabled
    Router ID : 2.2.2.2, Network Type <BROADCAST>, Cost: 10
    Transmit Delay is 1 sec, State <DR >, Priority 1
    Designated Router (ID) 2.2.2.2,  Interface Address 10.10.10.2
    Backup Designated Router (ID) 10.10.10.1,  Interface Address 10.10.10.1
    Multicast group memberships: OSPFAllRouters OSPFDesignatedRouters
    Timer intervals configured, Hello 10 Dead 40 wait 40 Retransmit 5
    Hello due in  7.717s
    Neighbor Count is 1, Adjacent neighbor count is 1"""

    result = parse_show_ip_ospf_interface(raw_result)
    expected = {
        'router_id': '2.2.2.2',
        'wait_time': '40',
        'Area_id': '0.0.0.1',
        'network_type': '<BROADCAST>',
        'cost': '10',
        'Backup_designated_router': '10.10.10.1',
        'retransmit_time': '5',
        'neighbor_count': '1',
        'bandwidth': '1000',
        'Interface_id': '1',
        'BDR_Interface_address': '10.10.10.1',
        'state': '<DR >',
        'hello_due_time': '7.717s',
        'Designated_router': '2.2.2.2',
        'Adjacent_neigbhor_count': '1',
        'internet_address': '10.10.10.2/24',
        'DR_Interface_address': '10.10.10.2',
        'dead_timer': '40',
        'hello_timer': '10',
        'transmit_delay': '1',
        'priority': '1'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_ospf_neighbor_detail():
    raw_result = """Neighbor 2.2.2.2,  interface address 10.10.10.2
    In the area 0.0.0.0 via interface 1
    Neighbor priority is 1, State is 2-Way, 1 state changes
    Neighbor is up for 9.240s
    DR is 2.2.2.2,BDR is 1.1.1.1
    Options 0  *|-|-|-|-|-|-|*
    Dead timer due in 30.763s
    Database Summary List 0
    Link State Request List 0
    Link State Retransmission List 0
    """

    result = parse_show_ip_ospf_neighbor_detail(raw_result)
    expected = {
        '2.2.2.2': {
            'dead_timer': '30.763s',
            'area': '0.0.0.0',
            'hello_timer': '9.240s',
            'state_change': 1,
            'interface_address': '10.10.10.2',
            'priority': 1,
            'link_req_list': 0,
            'state': '2-Way',
            'admin_state': 'up',
            'db_summary_list': 0,
            'Neighbor': '2.2.2.2',
            'BDR': '1.1.1.1',
            'interface': 1,
            'link_retrans_list': 0,
            'DR': '2.2.2.2',
            'options': 0}
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_ospf():

    raw_result = """OSPF Routing Process, Router ID:  2.2.2.2
                   This implementation conforms to RFC2328
                   RFC1583 Compatibility flag is disabled
                   Opaque Capability flag is disabled
                   Stub router advertisement is configured administratively
                   Initial SPF scheduling delay 200 millisec(s)
                   Minimum hold time between consecutive SPFs 1000 millisec(s)
                   Maximum hold time between consecutive SPFs 10000 millisec(s)
                   Hold time multiplier is currently 1
                   Number of external LSA 0. Checksum Sum 0x00000000
                   Number of opaque AS LSA 0. Checksum Sum 0x00000000
                   Number of areas attached to this router: 1
                   All adjacency changes are not logged
                   Area ID:  0.0.0.1
                     Number of interfaces in this area: Total: 1, Active:1
                     Number of fully adjacent neighbors in this area: 1
                     Area has no authentication
                     SPF algorithm last executed ago: 1m58s
                     SPF algorithm executed 15 times
                     Number of LSA 9
                     Number of router LSA 5. Checksum Sum 0x00018980
                     Number of network LSA 4. Checksum Sum 0x000091d3
                     Number of ABR summary LSA 0. Checksum Sum 0x00000000
                     Number of ASBR summary LSA 0. Checksum Sum 0x00000000
                     Number of NSSA LSA 0. Checksum Sum 0x00000000
                     Number of opaque link 0. Checksum Sum 0x00000000
                     Number of opaque area 0. Checksum Sum 0x00000000"""

    result = parse_show_ip_ospf(raw_result)
    expected = {
        'external_lsa': '0',
        'authentication_type': 'no authentication',
        'Area_id': '0.0.0.1',
        'no_of_lsa': '9',
        'interface_count': '1',
        'opaque_link': '0',
        'opaque_area': '0',
        'abr_summary_lsa': '0',
        'router_lsa': '5',
        'asbr_summary_lsa': '0',
        'nssa_lsa': '0',
        'fully_adj_neighbors': '1',
        'network_lsa': '4',
        'router': '2.2.2.2',
        'opaque_lsa': '0',
        'active_interfaces': '1',
        'no_of_area': '1'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_ospf_neighbor():

    raw_result = """\

    Neighbor ID Pri State    Dead Time Address    Interface  RXmtL RqstL DBsmL
----------------------------------------------------------------------------------------------------
2.2.2.2     1 Full/Backup   31.396s 10.0.1.1   1:10.0.1.2/24    0  0  0

    """

    result = parse_show_ip_ospf_neighbor(raw_result)
    expected = {
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

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_startup_config():

    raw_result = """\
Startup configuration:
!
!
!
!
!
vlan 1
    no shutdown
sftp-server
    enable
"""

    result = parse_show_startup_config(raw_result)
    expected = {
        'sftp-server': {
            'status': 'enable'
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_mirror():

    raw_result = """\
 name                                                            status
 --------------------------------------------------------------- --------------
 My_Session_1                                                    active
 Other-Session-2                                                 shutdown
"""

    result = parse_show_mirror(raw_result)
    expected = {
        'My_Session_1': {
            'name': 'My_Session_1',
            'status': 'active'
        },
        'Other-Session-2': {
            'name': 'Other-Session-2',
            'status': 'shutdown'
        }
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
 Mirror Session: My_Session_1
 Status: active
 Source: interface 2 both
 Source: interface 3 rx
 Destination: interface 1
 Output Packets: 123456789
 Output Bytes: 8912345678
"""

    result = parse_show_mirror(raw_result)
    expected = {
        'name': 'My_Session_1',
        'status': 'active',
        'source': [
            {
                'type': 'interface',
                'id': '2',
                'direction': 'both'
            },
            {
                'type': 'interface',
                'id': '3',
                'direction': 'rx'
            }],
        'destination': {
            'type': 'interface',
            'id': '1'
        },
        'output_packets': 123456789,
        'output_bytes': 8912345678
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff
