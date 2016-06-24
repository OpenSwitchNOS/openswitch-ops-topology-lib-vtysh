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

from topology_lib_vtysh.parser import (
    parse_show_interface,
    parse_show_interface_brief,
    parse_show_interface_vlan,
    parse_show_interface_mgmt,
    parse_show_interface_subinterface,
    parse_show_interface_subinterface_brief,
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
    parse_show_ip_interface,
    parse_show_ipv6_interface,
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
    parse_show_interface_loopback_brief,
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
    parse_show_ip_ospf_route,
    parse_show_startup_config,
    parse_show_mac_address_table,
    parse_show_tftp_server,
    parse_show_core_dump,
    parse_config_tftp_server_enable,
    parse_config_tftp_server_no_enable,
    parse_config_tftp_server_path,
    parse_config_tftp_server_no_path,
    parse_show_interface_lag,
    parse_show_mirror,
    parse_config_mirror_session_no_destination_interface,
    parse_show_snmp_community,
    parse_show_snmp_system,
    parse_show_snmp_trap,
    parse_diag_dump_lacp_basic,
    parse_show_snmpv3_users,
    parse_diag_dump,
    parse_show_events,
    parse_show_spanning_tree,
    parse_show_spanning_tree_mst,
    parse_show_spanning_tree_mst_config,
    parse_erase_startup_config,
    parse_config_tftp_server_secure_mode,
    parse_config_tftp_server_no_secure_mode,
    parse_show_radius_server,
    parse_show_aaa_authentication,
    parse_show_vlan_summary,
    parse_show_vlan_internal,
    parse_show_vrf,
    parse_show_access_list_hitcounts_ip_interface
    )


def test_parse_config_tftp_server_secure_mode():
    raw_result = "TFTP server secure mode is enabled successfully"

    result = parse_config_tftp_server_secure_mode(raw_result)
    expected = {
        'result': True
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_config_tftp_server_no_secure_mode():
    raw_result = "TFTP server secure mode is disabled successfully"

    result = parse_config_tftp_server_no_secure_mode(raw_result)
    expected = {
        'result': True
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_erase_startup_config():
    raw_result = "Delete statup row status : success"

    result = parse_erase_startup_config(raw_result)
    expected = {
        'erase_startup_config_status': 'success'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


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


def test_parse_show_core_dump():
    raw_result = """\
==============================================================================
Daemon Name     | Instance ID | Crash Reason                  | Timestamp
===========================================================================
ops-fand      2300          Illegal instruction            2016-04-19 06:10:06
kernel                                                     2016-04-19 06:09:56
==============================================================================
Total number of core dumps : 2
==============================================================================

        """
    result = parse_show_core_dump(raw_result)
    expected = {
        0: {'instance_id': 2300,
            'timestamp': '2016-04-19 06:10:06',
            'crash_reason': 'Illegal instruction',
            'daemon_name': 'ops-fand'},
        1: {'instance_id': 1,
            'timestamp': '2016-04-19 06:09:56',
            'crash_reason': 'unknown',
            'daemon_name': 'kernel'},
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = "No core dumps are present"
    result = parse_show_core_dump(raw_result)

    expected = {}
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

-------------------------------------------------------------------------------
VLAN    Name      Status   Reason         Reserved       Ports
-------------------------------------------------------------------------------
2       vlan2     up       ok                            7, 3, 8, vlan2, 1
1       vlan1     down     admin_down
69      vlan69    up       ok                            3.100, 8-1.2, vlan69
3       vlan3     up       ok                            vlan3, 1-1
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
        },
        '69': {
            'name': 'vlan69',
            'ports': ['3.100', '8-1.2', 'vlan69'],
            'reason': 'ok',
            'reserved': None,
            'status': 'up',
            'vlan_id': '69'
        },
        '3': {
            'name': 'vlan3',
            'ports': ['vlan3', '1-1'],
            'reason': 'ok',
            'reserved': None,
            'status': 'up',
            'vlan_id': '3'
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
Number of MAC addresses : 4

MAC Address          VLAN     Type       Port
--------------------------------------------------
00:00:00:00:00:01   1        dynamic    1
00:00:00:00:00:02   2        dynamic    2
00:00:00:00:00:02   3        dynamic    5
00:00:00:00:00:03   3        dynamic    3-1
00:00:00:00:00:04   4        dynamic    4-4
    """

    result = parse_show_mac_address_table(raw_result)

    expected = {
        'age_time': '300',
        'no_mac_address': '4',
        '00:00:00:00:00:01': {
            'vlan_id': '1',
            'from': 'dynamic',
            'port': '1'
        },
        '00:00:00:00:00:02': {
            'vlan_id': '3',
            'from': 'dynamic',
            'port': '5'
        },
        '00:00:00:00:00:03': {
            'vlan_id': '3',
            'from': 'dynamic',
            'port': '3-1'
        },
        '00:00:00:00:00:04': {
            'vlan_id': '4',
            'from': 'dynamic',
            'port': '4-4'
        },
        'vlans': {
            '1': {
                '00:00:00:00:00:01': {
                    'vlan_id': '1',
                    'from': 'dynamic',
                    'port': '1'
                },
            },
            '2': {
                '00:00:00:00:00:02': {
                    'vlan_id': '2',
                    'from': 'dynamic',
                    'port': '2'
                },
            },
            '3': {
                '00:00:00:00:00:02': {
                    'vlan_id': '3',
                    'from': 'dynamic',
                    'port': '5'
                },
                '00:00:00:00:00:03': {
                    'vlan_id': '3',
                    'from': 'dynamic',
                    'port': '3-1'
                },
            },
            '4': {
                '00:00:00:00:00:04': {
                    'vlan_id': '4',
                    'from': 'dynamic',
                    'port': '4-4'
                },
            }
        }
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
No MAC entries found
    """
    result = parse_show_mac_address_table(raw_result)
    assert not result


def test_parse_show_interface_mgmt():
    raw_result = """\
  Address Mode                  : dhcp
  IPv4 address/subnet-mask      :
  Default gateway IPv4          :
  IPv6 address/prefix           :
  IPv6 link local address/prefix:
  Default gateway IPv6          :
  Primary Nameserver            :
  Secondary Nameserver          :
    """

    result = parse_show_interface_mgmt(raw_result)

    expected = {
        'address_mode': 'dhcp',
        'ipv4': None,
        'default_gateway_ipv4': None,
        'ipv6': None,
        'ipv6_link_local': None,
        'default_gateway_ipv6': None,
        'primary_nameserver': None,
        'secondary_nameserver': None
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result2 = """\
  Address Mode                  : static
  IPv4 address/subnet-mask      : 20.1.1.2/30
  Default gateway IPv4          : 20.1.1.1
  IPv6 address/prefix           : 2011::2/64
  IPv6 link local address/prefix: fe80::4a0f:cfff:feaf:6358/64
  Default gateway IPv6          : 2011::1
  Primary Nameserver            : 232.54.54.54
  Secondary Nameserver          : 232.54.54.44
    """

    result2 = parse_show_interface_mgmt(raw_result2)

    expected2 = {
        'address_mode': 'static',
        'ipv4': '20.1.1.2/30',
        'default_gateway_ipv4': '20.1.1.1',
        'ipv6': '2011::2/64',
        'ipv6_link_local': 'fe80::4a0f:cfff:feaf:6358/64',
        'default_gateway_ipv6': '2011::1',
        'primary_nameserver': '232.54.54.54',
        'secondary_nameserver': '232.54.54.44'
    }

    ddiff2 = DeepDiff(result2, expected2)
    assert not ddiff2


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
        'ipv4_secondary': None,
        'ipv6': None,
        'ipv6_secondary': None,
        'qos_trust': None,
        'qos_dscp': None,
        'qos_queue_profile': None,
        'qos_schedule_profile': None,
        'qos_schedule_profile_status': None
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
 qos trust none
 qos queue-profile default
 qos schedule-profile default, status is strict
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
        'ipv4_secondary': None,
        'ipv6': None,
        'ipv6_secondary': None,
        'qos_trust': 'none',
        'qos_dscp': None,
        'qos_queue_profile': 'default',
        'qos_schedule_profile': 'default',
        'qos_schedule_profile_status': 'strict'
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
 qos trust none
 qos queue-profile default
 qos schedule-profile default
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
        'ipv4_secondary': None,
        'ipv6': '2002::1/64',
        'ipv6_secondary': None,
        'qos_trust': 'none',
        'qos_dscp': None,
        'qos_queue_profile': 'default',
        'qos_schedule_profile': 'default',
        'qos_schedule_profile_status': None
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
 qos trust none
 qos queue-profile default
 qos schedule-profile default
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
        'ipv4_secondary': None,
        'ipv6': '2002::1/64',
        'ipv6_secondary': None,
        'qos_trust': 'none',
        'qos_dscp': None,
        'qos_queue_profile': 'default',
        'qos_schedule_profile': 'default',
        'qos_schedule_profile_status': None
    }

    ddiff4 = DeepDiff(result4, expected4)
    assert not ddiff4

    raw_result5 = """\

Interface 1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv4 address 10.1.1.1/24
 IPv4 address 10.1.1.2/24 secondary
 IPv6 address 2001::1/12
 IPv6 address 2001::2/12 secondary
 MTU 0
 Full-duplex
 qos trust none
 qos queue-profile default
 qos schedule-profile default
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

    result5 = parse_show_interface(raw_result5)

    expected5 = {
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
        'ipv4': '10.1.1.1/24',
        'ipv4_secondary': '10.1.1.2/24',
        'ipv6': '2001::1/12',
        'ipv6_secondary': '2001::2/12',
        'qos_trust': 'none',
        'qos_dscp': None,
        'qos_queue_profile': 'default',
        'qos_schedule_profile': 'default',
        'qos_schedule_profile_status': None
    }

    ddiff5 = DeepDiff(result5, expected5)
    assert not ddiff5

    raw_result6 = """\

Interface 1-1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv4 address 10.1.1.1/24
 IPv4 address 10.1.1.2/24 secondary
 IPv6 address 2001::1/12
 IPv6 address 2001::2/12 secondary
 MTU 0
 Full-duplex
 qos trust none
 qos queue-profile default
 qos schedule-profile default
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

    result6 = parse_show_interface(raw_result6)

    expected6 = {
        'admin_state': 'up',
        'autonegotiation': True,
        'conection_type': 'Full-duplex',
        'hardware': 'Ethernet',
        'input_flow_control': False,
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'output_flow_control': False,
        'port': "1-1",
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
        'ipv4': '10.1.1.1/24',
        'ipv4_secondary': '10.1.1.2/24',
        'ipv6': '2001::1/12',
        'ipv6_secondary': '2001::2/12',
        'qos_trust': 'none',
        'qos_dscp': None,
        'qos_queue_profile': 'default',
        'qos_schedule_profile': 'default',
        'qos_schedule_profile_status': None
    }

    ddiff6 = DeepDiff(result6, expected6)
    assert not ddiff6

    raw_result7 = """\

Interface 7-1 is down (Administratively down)
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

    result7 = parse_show_interface(raw_result7)

    expected7 = {
        'admin_state': 'down',
        'autonegotiation': True,
        'conection_type': 'Half-duplex',
        'hardware': 'Ethernet',
        'input_flow_control': False,
        'interface_state': 'down',
        'mac_address': '70:72:cf:d7:d3:dd',
        'mtu': 0,
        'output_flow_control': False,
        'port': "7-1",
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
        'ipv4_secondary': None,
        'ipv6': None,
        'ipv6_secondary': None,
        'qos_trust': None,
        'qos_dscp': None,
        'qos_queue_profile': None,
        'qos_schedule_profile': None,
        'qos_schedule_profile_status': None
    }

    ddiff7 = DeepDiff(result7, expected7)
    assert not ddiff7


def test_parse_show_interface_vlan():
    raw_result = """\

Interface vlan10 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 48:0f:cf:af:73:37
 IPv4 address 10.0.0.1/24
 RX
       L3:
            ucast: 34432 packets, 12323376 bytes
            mcast: 3 packets, 322 bytes
 TX
       L3:
            ucast: 23 packets, 32344 bytes
            mcast: 2 packets, 5023 bytes

    """

    result = parse_show_interface_vlan(raw_result)

    expected = {
        'state_description': None,
        'rx_l3_ucast_packets': 34432,
        'tx_l3_mcast_bytes': 3,
        'interface_state': 'up',
        'rx_l3_mcast_bytes': 322,
        'mac_address': '48:0f:cf:af:73:37',
        'tx_l3_ucast_bytes': 32344,
        'hardware': 'Ethernet',
        'rx_l3_ucast_bytes': 12323376,
        'tx_l3_mcast_packets': 2,
        'ipv4': '10.0.0.1/24',
        'ipv4_secondary': None,
        'ipv6': None,
        'admin_state': 'up',
        'rx_l3_mcast_packets': 3,
        'tx_l3_ucast_packets': 23,
        'vlan_number': 10,
        'ipv6_secondary': None
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_interface_subinterface():
    raw_result = """\
Interface 3.10 is up.

 Admin state is up
 Parent interface is 3
 Encapsulation dot1Q 100
 Hardware: Ethernet, MAC Address: 70:72:cf:fd:e1:0e
 IPv4 address 30.0.0.1/24
 Input flow-control is off, output flow-control is off
 RX
       L3:
            ucast: 15 packets, 0 bytes
            mcast: 0 packets, 0 bytes
 TX
       L3:
            ucast: 0 packets, 20 bytes
            mcast: 0 packets, 0 bytes

Interface 3.20 is up.

 Admin state is up
 Parent interface is 3
 Encapsulation dot1Q 20
 Hardware: Ethernet, MAC Address: 70:72:cf:fd:e1:0e
 IPv4 address 20.0.0.1/24
 Input flow-control is off, output flow-control is off
 RX
       L3:
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
 TX
       L3:
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes

"""
    result = parse_show_interface_subinterface(raw_result)

    expected = {
        10: {'admin_state': 'down',
             'encapsulation_dot1q': 100,
             'hardware': 'Ethernet',
             'admin_state': 'up',
             'input_flow_control': False,
             'interface_state': 'up',
             'mac_address': '70:72:cf:fd:e1:0e',
             'output_flow_control': False,
             'parent_interface': 3,
             'port': 3,
             'rx_mcast_packets': 0,
             'rx_mcast_bytes': 0,
             'rx_ucast_packets': 15,
             'rx_ucast_bytes': 0,
             'subinterface': 10,
             'tx_mcast_packets': 0,
             'tx_mcast_bytes': 0,
             'tx_ucast_packets': 0,
             'tx_ucast_bytes': 20,
             'ipv6': None,
             'ipv4': '30.0.0.1/24'},
        20: {'admin_state': 'down',
             'encapsulation_dot1q': 20,
             'hardware': 'Ethernet',
             'admin_state': 'up',
             'input_flow_control': False,
             'interface_state': 'up',
             'mac_address': '70:72:cf:fd:e1:0e',
             'output_flow_control': False,
             'parent_interface': 3,
             'port': 3,
             'rx_mcast_packets': 0,
             'rx_mcast_bytes': 0,
             'rx_ucast_packets': 0,
             'rx_ucast_bytes': 0,
             'subinterface': 20,
             'tx_mcast_packets': 0,
             'tx_mcast_bytes': 0,
             'tx_ucast_packets': 0,
             'tx_ucast_bytes': 0,
             'ipv6': None,
             'ipv4': '20.0.0.1/24'}
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_interface_subinterface_brief():
    raw_result = """\
--------------------------------------------------------------------------------
Ethernet      VLAN    Type Mode   Status  Reason                   Speed    Port
Interface                                                          (Mb/s)   Ch#
--------------------------------------------------------------------------------
 4.1            40    eth  routed down   Administratively down     auto     --
 4.2            20    eth  routed down   Administratively down     auto     --
 3-1.300        300   eth  routed down   Administratively down     auto     --
 4-4.689        689   eth  routed up                               auto     --
     """  # noqa

    result = parse_show_interface_subinterface_brief(raw_result)
    expected = [
        {
            'vlan_id': 40,
            'subinterface': '4.1',
            'type': 'eth',
            'mode': 'routed',
            'status': 'down',
            'reason': 'Administratively down    ',
            'speed': 'auto',
            'port_ch': '--'
        },
        {
            'vlan_id': 20,
            'subinterface': '4.2',
            'type': 'eth',
            'mode': 'routed',
            'status': 'down',
            'reason': 'Administratively down    ',
            'speed': 'auto',
            'port_ch': '--'
        },
        {
            'vlan_id': 300,
            'subinterface': '3-1.300',
            'type': 'eth',
            'mode': 'routed',
            'status': 'down',
            'reason': 'Administratively down    ',
            'speed': 'auto',
            'port_ch': '--'
        },
        {
            'vlan_id': 689,
            'subinterface': '4-4.689',
            'type': 'eth',
            'mode': 'routed',
            'status': 'up',
            'reason': '',
            'speed': 'auto',
            'port_ch': '--'
        }
    ]

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
        'agg_mode': None,
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
        'qos_trust': None,
        'qos_dscp': None,
        'qos_queue_profile': None,
        'qos_schedule_profile': None
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
Fallback              : true
Fallback mode         : all_active
Fallback timeout      : 300
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
            'fallback_mode': None,
            'fallback_timeout': None,
            'hash': 'l3-src-dst',
            'mode': 'off'
        },
        'lag2': {
            'name': 'lag2',
            'interfaces': [],
            'heartbeat_rate': 'slow',
            'fallback': True,
            'fallback_mode': 'all_active',
            'fallback_timeout': '300',
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

    raw_result = """\
Port                           : 1-1
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
        'port': '1-1',
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

    raw_result = """\
Port                           : 1-1.100
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
        'port': '1-1.100',
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


def test_parse_show_ip_interface():
    raw_result = """\

Interface 1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv4 address 10.1.1.1/24
 IPv4 address 10.1.1.2/24 secondary
 MTU 0
 RX
            ucast: 0 packets, 0 bytes
            mcast: 10 packets, 0 bytes
 TX
            ucast: 0 packets, 0 bytes
            mcast: 10 packets, 0 bytes
    """

    result = parse_show_ip_interface(raw_result)

    expected = {
        'admin_state': 'up',
        'hardware': 'Ethernet',
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'port': 1,
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 10,
        'rx_l3_mcast_bytes': 0,
        'state_description': None,
        'state_information': None,
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 10,
        'tx_l3_mcast_bytes': 0,
        'ipv4': '10.1.1.1/24',
        'ipv4_secondary': '10.1.1.2/24',
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result2 = """\

Interface 1-1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv4 address 10.1.1.1/24
 IPv4 address 10.1.1.2/24 secondary
 MTU 0
 RX
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
 TX
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
    """

    result2 = parse_show_ip_interface(raw_result2)

    expected2 = {
        'admin_state': 'up',
        'hardware': 'Ethernet',
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'port': "1-1",
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 0,
        'rx_l3_mcast_bytes': 0,
        'state_description': None,
        'state_information': None,
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 0,
        'tx_l3_mcast_bytes': 0,
        'ipv4': '10.1.1.1/24',
        'ipv4_secondary': '10.1.1.2/24',
    }

    ddiff2 = DeepDiff(result2, expected2)
    assert not ddiff2

    raw_result3 = """\

Interface 15 is down (Administratively down)
 Admin state is down
 State information: admin_down
 Hardware: Ethernet, MAC Address: 48:0f:cf:af:d4:c3
 MTU 1500
 RX
          ucast: 0 packets, 0 bytes
          mcast: 0 packets, 0 bytes
 TX
          ucast: 0 packets, 0 bytes
          mcast: 0 packets, 0 bytes
    """

    result3 = parse_show_ip_interface(raw_result3)

    expected3 = {
        'admin_state': 'down',
        'hardware': 'Ethernet',
        'interface_state': 'down',
        'mac_address': '48:0f:cf:af:d4:c3',
        'mtu': 1500,
        'port': 15,
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 0,
        'rx_l3_mcast_bytes': 0,
        'state_description': 'Administratively down',
        'state_information': 'admin_down',
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 0,
        'tx_l3_mcast_bytes': 0,
        'ipv4': None,
        'ipv4_secondary': None,
    }

    ddiff3 = DeepDiff(result3, expected3)
    assert not ddiff3


def test_parse_show_ipv6_interface():
    raw_result = """\

Interface 1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv6 address 2001::1/12
 IPv6 address 2001::2/12 secondary
 MTU 0
 RX
            ucast: 0 packets, 0 bytes
            mcast: 10 packets, 0 bytes
 TX
            ucast: 0 packets, 0 bytes
            mcast: 10 packets, 0 bytes
    """

    result = parse_show_ipv6_interface(raw_result)

    expected = {
        'admin_state': 'up',
        'hardware': 'Ethernet',
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'port': 1,
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 10,
        'rx_l3_mcast_bytes': 0,
        'state_description': None,
        'state_information': None,
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 10,
        'tx_l3_mcast_bytes': 0,
        'ipv6': '2001::1/12',
        'ipv6_secondary': '2001::2/12'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result2 = """\

Interface 1-1 is up
 Admin state is up
 Hardware: Ethernet, MAC Address: 70:72:cf:75:25:70
 IPv6 address 2001::1/12
 IPv6 address 2001::2/12 secondary
 MTU 0
 RX
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
 TX
            ucast: 0 packets, 0 bytes
            mcast: 0 packets, 0 bytes
    """

    result2 = parse_show_ipv6_interface(raw_result2)

    expected2 = {
        'admin_state': 'up',
        'hardware': 'Ethernet',
        'interface_state': 'up',
        'mac_address': '70:72:cf:75:25:70',
        'mtu': 0,
        'port': "1-1",
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 0,
        'rx_l3_mcast_bytes': 0,
        'state_description': None,
        'state_information': None,
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 0,
        'tx_l3_mcast_bytes': 0,
        'ipv6': '2001::1/12',
        'ipv6_secondary': '2001::2/12'
    }

    ddiff2 = DeepDiff(result2, expected2)
    assert not ddiff2

    raw_result3 = """\

Interface 15 is down (Administratively down)
 Admin state is down
 State information: admin_down
 Hardware: Ethernet, MAC Address: 48:0f:cf:af:d4:c3
 MTU 1500
 RX
          ucast: 0 packets, 0 bytes
          mcast: 0 packets, 0 bytes
 TX
          ucast: 0 packets, 0 bytes
          mcast: 0 packets, 0 bytes
    """

    result3 = parse_show_ipv6_interface(raw_result3)

    expected3 = {
        'admin_state': 'down',
        'hardware': 'Ethernet',
        'interface_state': 'down',
        'mac_address': '48:0f:cf:af:d4:c3',
        'mtu': 1500,
        'port': 15,
        'rx_l3_ucast_packets': 0,
        'rx_l3_ucast_bytes': 0,
        'rx_l3_mcast_packets': 0,
        'rx_l3_mcast_bytes': 0,
        'state_description': 'Administratively down',
        'state_information': 'admin_down',
        'tx_l3_ucast_packets': 0,
        'tx_l3_ucast_bytes': 0,
        'tx_l3_mcast_packets': 0,
        'tx_l3_mcast_bytes': 0,
        'ipv6': None,
        'ipv6_secondary': None,
    }

    ddiff3 = DeepDiff(result3, expected3)
    assert not ddiff3


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
    raw_result_networkunreachable = """\
connect: Network is unreachable
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

    result = parse_ping_repetitions(raw_result_networkunreachable)
    expected = {
        'transmitted': None
    }

    assert not ddiff


def test_parse_ping6_repetitions():
    raw_result = """\
PING 2000::2 (2000::2) 100(128) bytes of data.
108 bytes from 2000::2: icmp_seq=1 ttl=64 time=0.465 ms

--- 2000::2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.465/0.465/0.465/0.000 ms
    """
    raw_result_networkunreachable = """\
connect: Network is unreachable
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
    result = parse_ping_repetitions(raw_result_networkunreachable)
    expected = {
        'transmitted': None
    }

    assert not ddiff


def test_parse_ping():
    raw_result = """\
    PING 10.1.1.10 (10.1.1.10) 100(128) bytes of data.

From 10.1.1.1 icmp_seq=1 Destination Host Unreachable
From 10.1.1.1 icmp_seq=2 Destination Host Unreachable
From 10.1.1.1 icmp_seq=3 Destination Host Unreachable
From 10.1.1.1 icmp_seq=4 Destination Host Unreachable

--- 10.1.1.10 ping statistics ---
5 packets transmitted, 0 received, +4 errors, 100% packet loss, time 4001ms"""

    result = parse_ping(raw_result)

    expected = {
        'loss_pc': 100,
        'reason': 'Destination unreachable'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_ping6():
    raw_result = """\
    PING 1002::3(1002::3) 100 data bytes
From 1002::2 icmp_seq=1 Destination unreachable: Address unreachable
From 1002::2 icmp_seq=2 Destination unreachable: Address unreachable
From 1002::2 icmp_seq=3 Destination unreachable: Address unreachable
From 1002::2 icmp_seq=4 Destination unreachable: Address unreachable
From 1002::2 icmp_seq=5 Destination unreachable: Address unreachable

--- 1002::3 ping statistics ---
5 packets transmitted, 0 received, +5 errors, 100% packet loss, time 4000ms"""

    result = parse_ping6(raw_result)

    expected = {
        'loss_pc': 100,
        'reason': 'Destination unreachable'
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
*172.16.0.24/30, 1 unicast next-hops
    *via 1.5, [0/0], connected

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
            },
            {
                'id': '172.16.0.24',
                'prefix': '30',
                'selected': True,
                'next_hops': [
                    {
                        'selected': True,
                        'via': '1.5',
                        'distance': '0',
                        'from': 'connected',
                        'metric': '0',
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
logging 20.20.20.1 udp severity info
logging 2001::1 severity warning
logging syserver
logging 10.10.10.10 tcp 400 severity debug
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
interface lag 1
    lacp mode passive
interface 4.2
    no shutdown
    encapsulation dot1Q 20
    ip address 20.0.0.1/24
sftp-server
    enable
mirror session foo
ipv6 route 2020::3/128 1
ip route 140.1.1.10/32 1
ip route 140.1.1.30/32 1
ipv6 route 2020::2/128 1
"""

    result = parse_show_running_config(raw_result)
    result_startup = parse_show_startup_config(raw_result)

    expected = {
        'syslog_remotes': {
            '0': {
                'remote_host': '20.20.20.1',
                'transport': 'udp',
                'severity': 'info'
            },
            '1': {
                'remote_host': '2001::1',
                'severity': 'warning'
            },
            '2': {
                'remote_host': 'syserver',
            },
            '3': {
                'remote_host': '10.10.10.10',
                'port': '400',
                'transport': 'tcp',
                'severity': 'debug'
            }
        },
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
            'subint': {'4.2': {
                'dot1q': '20',
                'admin': 'up',
                'ipv4': '20.0.0.1/24'}
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
            },
            'lag': {'1': {'lacp_mode': 'passive'}}
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
        },
        'ip_routes': {
            '2020::2': {
                'via': '1',
                'prefix': '128',
                'network': '2020::2',
            },
            '2020::3': {
                'via': '1',
                'prefix': '128',
                'network': '2020::3',
            },
            '140.1.1.10': {
                'via': '1',
                'prefix': '32',
                'network': '140.1.1.10',
            },
            '140.1.1.30': {
                'via': '1',
                'prefix': '32',
                'network': '140.1.1.30',
            }
        },
        'mirror_session':
        {
            'foo': 'foo'
        },
        'qos_trust':
        {
        },
        'qos_cos_map':
        {
        },
        'qos_dscp_map':
        {
        },
        'qos_schedule_profile':
        {
        },
        'qos_queue_profile':
        {
        },
        'apply_qos':
        {
        },
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff
    # Startup Config and Running config are similar, hence using same test
    # case to test both
    ddiff = DeepDiff(result_startup, expected)
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
10.1.64.0/18,  1 unicast next-hops
        via  lo2,  [0/0],  connected
10.2.64.0/18,  1 unicast next-hops
        via  1-1,  [0/0],  connected
        via  4-4.100,  [0/0],  connected
        via  9.4,  [0/0],  connected

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
        },
        {
            'id': '10.1.64.0',
            'prefix': '18',
            'next_hops': [
                {
                    'via': 'lo2',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                }
            ]
        },
        {
            'id': '10.2.64.0',
            'prefix': '18',
            'next_hops': [
                {
                    'via': '1-1',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                },
                {
                    'via': '4-4.100',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                },
                {
                    'via': '9.4',
                    'distance': '0',
                    'from': 'connected',
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
2004:0:1::/48,  1 unicast next-hops
        via  lo2,  [0/0],  connected
2005:0:1::/48,  1 unicast next-hops
        via  1-1,  [0/0],  connected
        via  9.4,  [0/0],  connected
        via  4-1.100,  [0/0],  connected
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
        {
            'id': '2004:0:1::/48',
            'next_hops': [
                {
                    'via': 'lo2',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                }
            ]
        },
        {
            'id': '2005:0:1::/48',
            'next_hops': [
                {
                    'via': '1-1',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                },
                {
                    'via': '9.4',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                },
                {
                    'via': '4-1.100',
                    'distance': '0',
                    'from': 'connected',
                    'metric': '0'
                }
            ]
        }
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
IP Address                                     Hostname          Client-\
id         Lease time(min)  MAC-Address        Set tags
------------------------------------------------------------------------\
-------------------------------------------------------
192.168.20.48                                  *                 *      \
           1440             aa:bb:cc:dd:ee:ff  *
10.2.2.2                                       *                 *      \
           1440             11:11:11:11:11:11  *


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
    raw_result = """\
sFlow Configuration - Interface 1-1
-----------------------------------------
sFlow                         enable
Sampling Rate                 15
Number of Samples             20
    """

    result = parse_show_sflow_interface(raw_result)

    expected = {
        'interface': '1-1',
        'sflow': 'enable',
        'sampling_rate': 15,
        'number_of_samples': 20
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """\
sFlow Configuration - Interface 4-4
-----------------------------------------
sFlow                         disabled
Sampling Rate                 20
Number of Samples             18
    """

    result = parse_show_sflow_interface(raw_result)

    expected = {
        'interface': '4-4',
        'sflow': 'disabled',
        'sampling_rate': 20,
        'number_of_samples': 18
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

    expected = {
        'daemon': 'ops-lldpd',
        'syslog': 'INFO',
        'file': 'INFO',
    }

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
        'hello_timer': '10',
        'Backup_designated_router': '10.10.10.1',
        'hello_due_time': '7.717s',
        'retransmit_time': '5',
        'neighbor_count': '1',
        'state': '<DR >',
        'Interface_id': '1',
        'priority': '1',
        'BDR_Interface_address': '10.10.10.1',
        'bandwidth': '1000',
        'cost': '10',
        'Adjacent_neigbhor_count': '1',
        'internet_address': '10.10.10.2/24',
        'Designated_router': '10.10.10.1',
        'dead_timer': '40',
        'network_type': '<BROADCAST>',
        'transmit_delay': '1',
        'DR_Interface_address': '10.10.10.1'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """Interface 2-1 BW 1000 Mbps  <up,BROADCAST,up >
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
        'hello_timer': '10',
        'Backup_designated_router': '10.10.10.1',
        'hello_due_time': '7.717s',
        'retransmit_time': '5',
        'neighbor_count': '1',
        'state': '<DR >',
        'Interface_id': '2-1',
        'priority': '1',
        'BDR_Interface_address': '10.10.10.1',
        'bandwidth': '1000',
        'cost': '10',
        'Adjacent_neigbhor_count': '1',
        'internet_address': '10.10.10.2/24',
        'Designated_router': '10.10.10.1',
        'dead_timer': '40',
        'network_type': '<BROADCAST>',
        'transmit_delay': '1',
        'DR_Interface_address': '10.10.10.1'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """Interface 3.100 BW 1000 Mbps  <up,BROADCAST,up >
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
        'hello_timer': '10',
        'Backup_designated_router': '10.10.10.1',
        'hello_due_time': '7.717s',
        'retransmit_time': '5',
        'neighbor_count': '1',
        'state': '<DR >',
        'Interface_id': '3.100',
        'priority': '1',
        'BDR_Interface_address': '10.10.10.1',
        'bandwidth': '1000',
        'cost': '10',
        'Adjacent_neigbhor_count': '1',
        'internet_address': '10.10.10.2/24',
        'Designated_router': '10.10.10.1',
        'dead_timer': '40',
        'network_type': '<BROADCAST>',
        'transmit_delay': '1',
        'DR_Interface_address': '10.10.10.1'
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """Interface 4-1.20 BW 1000 Mbps  <up,BROADCAST,up >
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
        'hello_timer': '10',
        'Backup_designated_router': '10.10.10.1',
        'hello_due_time': '7.717s',
        'retransmit_time': '5',
        'neighbor_count': '1',
        'state': '<DR >',
        'Interface_id': '4-1.20',
        'priority': '1',
        'BDR_Interface_address': '10.10.10.1',
        'bandwidth': '1000',
        'cost': '10',
        'Adjacent_neigbhor_count': '1',
        'internet_address': '10.10.10.2/24',
        'Designated_router': '10.10.10.1',
        'dead_timer': '40',
        'network_type': '<BROADCAST>',
        'transmit_delay': '1',
        'DR_Interface_address': '10.10.10.1'
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

    raw_result = """Neighbor 2.2.2.2,  interface address 10.10.10.2
    In the area 0.0.0.0 via interface 1-1
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
            'interface': '1-1',
            'link_retrans_list': 0,
            'DR': '2.2.2.2',
            'options': 0}
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """Neighbor 2.2.2.2,  interface address 10.10.10.2
    In the area 0.0.0.0 via interface 1.100
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
            'interface': '1.100',
            'link_retrans_list': 0,
            'DR': '2.2.2.2',
            'options': 0}
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff

    raw_result = """Neighbor 2.2.2.2,  interface address 10.10.10.2
    In the area 0.0.0.0 via interface 4-1.20
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
            'interface': '4-1.20',
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
                 Area ID:  0.0.0.0 (Backbone)
                   Number of interfaces in this area: Total: 1, Active:1
                   Number of fully adjacent neighbors in this area: 0
                   Area has no authentication
                   SPF algorithm last executed ago: 11.354s
                   SPF algorithm executed 1 times
                   Number of LSA 2
                   Number of router LSA 2. Checksum Sum 0x00008d77
                   Number of network LSA 0. Checksum Sum 0x00000000
                   Number of ABR summary LSA 0. Checksum Sum 0x00000000
                   Number of ASBR summary LSA 0. Checksum Sum 0x00000000
                   Number of NSSA LSA 0. Checksum Sum 0x00000000
                   Number of opaque link 0. Checksum Sum 0x00000000
                   Number of opaque area 0. Checksum Sum 0x00000000"""

    result = parse_show_ip_ospf(raw_result)
    expected = {
        'router_id': '2.2.2.2',
        'no_of_area': '1',
        '0.0.0.0': {
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
            'nssa_lsa': 0}
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
        '2.2.2.2': {
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
    }

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_ip_ospf_route():
    raw_result = """
Codes: N - Network, R - Router, IA - Inter Area,
       E1 - External Type 1, E2 - External Type 2
============ OSPF network routing table ============
N    12.0.0.0/24           [1] area: 0.0.0.0
                           directly attached to 2
N    14.0.0.0/24           [1] area: 0.0.0.0
                           directly attached to 6
N    13.0.0.0/24           [1] area: 0.0.0.0
                           directly attached to 5
N    15.0.0.0/24           [1] area: 0.0.0.0
                           directly attached to 1-1
N    16.0.0.0/24           [1] area: 0.0.0.0
                           directly attached to 8.10
N    17.0.0.0/24           [1] area: 0.0.0.0
                           directly attached to 7-1.20

============ OSPF router routing table =============
R    1.0.0.1               [1] area: 0.0.0.0, ASBR
                           via 12.0.0.1, 2
                           via 13.0.0.1, 5
                           via 14.0.0.1, 6
                           via 15.0.0.1, 1-1
                           via 16.0.0.1, 8.10
                           via 17.0.0.1, 7-1.20

============ OSPF external routing table ===========
N E2 100.0.0.0/24          [1/20] tag: 0
                           via 12.0.0.1, 2
                           via 13.0.0.1, 5
                           via 14.0.0.1, 6
                           via 15.0.0.1, 1-1
                           via 16.0.0.1, 8.10
                           via 17.0.0.1, 7-1.20

    """

    expected_result = {
        'network routing table': [
            {'hops': '1',
             'area': '0.0.0.0',
             'ip_address': '12.0.0.0/24',
             'port': '2',
             'network': 'N'},
            {'hops': '1',
             'area': '0.0.0.0',
             'ip_address': '14.0.0.0/24',
             'port': '6',
             'network': 'N'},
            {'hops': '1',
             'area': '0.0.0.0',
             'ip_address': '13.0.0.0/24',
             'port': '5',
             'network': 'N'},
            {'hops': '1',
             'area': '0.0.0.0',
             'ip_address': '15.0.0.0/24',
             'port': '1-1',
             'network': 'N'},
            {'hops': '1',
             'area': '0.0.0.0',
             'ip_address': '16.0.0.0/24',
             'port': '8.10',
             'network': 'N'},
            {'hops': '1',
             'area': '0.0.0.0',
             'ip_address': '17.0.0.0/24',
             'port': '7-1.20',
             'network': 'N'}
        ],
        'router routing table': [
            {'hops': '1', 'router': 'R', 'asbr': 'ASBR',
             'ip_address': '1.0.0.1', 'area': '0.0.0.0'},
            {'via_ip': '12.0.0.1', 'via_port': '2'},
            {'via_ip': '13.0.0.1', 'via_port': '5'},
            {'via_ip': '14.0.0.1', 'via_port': '6'},
            {'via_ip': '15.0.0.1', 'via_port': '1-1'},
            {'via_ip': '16.0.0.1', 'via_port': '8.10'},
            {'via_ip': '17.0.0.1', 'via_port': '7-1.20'}
        ],
        'external routing table': [
            {'hops': '1', 'metric': '20', 'tag': '0', 'router': 'N',
             'ip_address': '100.0.0.0/24', 'external_type': 'E2'},
            {'via_ip': '12.0.0.1', 'via_port': '2'},
            {'via_ip': '13.0.0.1', 'via_port': '5'},
            {'via_ip': '14.0.0.1', 'via_port': '6'},
            {'via_ip': '15.0.0.1', 'via_port': '1-1'},
            {'via_ip': '16.0.0.1', 'via_port': '8.10'},
            {'via_ip': '17.0.0.1', 'via_port': '7-1.20'}
        ],
    }

    result = parse_show_ip_ospf_route(raw_result)
    ddiff = DeepDiff(result, expected_result)

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


def test_parse_config_mirror_session_no_destination_interface():
    raw_result = (
        "Destination interface removed, mirror session mirror1 shutdown"
        )

    result = parse_config_mirror_session_no_destination_interface(raw_result)
    ddiff = DeepDiff(result, raw_result)
    assert not ddiff


def test_parse_diag_dump_lacp_basic():
    raw_result = """\
=========================================================================
[Start] Feature lacp Time : Fri Apr 15 17:38:32 2016

=========================================================================
-------------------------------------------------------------------------
[Start] Daemon ops-lacpd
-------------------------------------------------------------------------
System Ports:
================ Ports ================
Port 5:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 5
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port bridge_normal:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : bridge_normal
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port 1:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 1
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port lag10:
    lacp                 : active
    lag_member_speed     : 0
    configured_members   : 3 2 9-1
    eligible_members     : 3 2 9-1
    participant_members  :
    interface_count      : 0
Port 4:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 4
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port 4-1:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 4-1
    eligible_members     :
    participant_members  :
    interface_count      : 0

LAG interfaces: \nPort lag10:
    configured_members   : 3 2 9-1
    eligible_members     : 3 2 9-1
    participant_members  :

LACP PDUs counters: \nLAG lag10:
 Configured interfaces:
  Interface: 3
    lacp_pdus_sent: 0
    marker_response_pdus_sent: 0
    lacp_pdus_received: 0
    marker_pdus_received: 0
  Interface: 2
    lacp_pdus_sent: 0
    marker_response_pdus_sent: 0
    lacp_pdus_received: 0
    marker_pdus_received: 0
  Interface: 5-1
    lacp_pdus_sent: 0
    marker_response_pdus_sent: 0
    lacp_pdus_received: 0
    marker_pdus_received: 0

LACP state: \nLAG lag10:
 Configured interfaces:
  Interface: 3
    actor_oper_port_state \n\
        lacp_activity:1 time_out:1 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:1 expired:0
    partner_oper_port_state \n\
        lacp_activity:0 time_out:0 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:0 expired:0
    lacp_control
       begin:0 actor_churn:0 partner_churn:0 ready_n:0 selected:0 \
port_moved:0 ntt:0 port_enabled:0
  Interface: 2
    actor_oper_port_state \n\
       lacp_activity:1 time_out:1 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:1 expired:0
    partner_oper_port_state \n\
       lacp_activity:0 time_out:0 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:0 expired:0
    lacp_control
       begin:0 actor_churn:0 partner_churn:0 ready_n:0 selected:0 \
port_moved:0 ntt:0 port_enabled:0 \n\
  Interface: 3-1
    actor_oper_port_state \n\
        lacp_activity:1 time_out:1 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:1 expired:0
    partner_oper_port_state \n\
        lacp_activity:0 time_out:0 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:0 expired:0
    lacp_control
       begin:0 actor_churn:0 partner_churn:0 ready_n:0 selected:0 \
port_moved:0 ntt:0 port_enabled:0

-------------------------------------------------------------------------
[End] Daemon ops-lacpd
-------------------------------------------------------------------------
-------------------------------------------------------------------------
[Start] Daemon ops-portd
-------------------------------------------------------------------------
Configuration file for lag10:
Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: load balancing (xor)
Transmit Hash Policy: layer2 (0)
MII Status: down
MII Polling Interval (ms): 0
Up Delay (ms): 0
Down Delay (ms): 0


-------------------------------------------------------------------------
[End] Daemon ops-portd
-------------------------------------------------------------------------
=========================================================================
[End] Feature lacp
=========================================================================
Diagnostic dump captured for feature lacp
    """

    result = parse_diag_dump_lacp_basic(raw_result)

    expected1 = {
        'Counters': {
            '10': {
                '2': {
                    'marker_pdus_received': 0,
                    'marker_response_pdus_sent': 0,
                    'lacp_pdus_received': 0,
                    'lacp_pdus_sent': 0
                },
                '3': {
                    'marker_pdus_received': 0,
                    'marker_response_pdus_sent': 0,
                    'lacp_pdus_received': 0,
                    'lacp_pdus_sent': 0
                },
                '5-1': {
                    'marker_pdus_received': 0,
                    'marker_response_pdus_sent': 0,
                    'lacp_pdus_received': 0,
                    'lacp_pdus_sent': 0
                }
            }
        },
        'State': {
            '10': {
                2: {
                    'partner_oper_port_state': {
                        'distributing': 0,
                        'expired': 0,
                        'time_out': 0,
                        'aggregation': 1,
                        'sync': 0,
                        'lacp_activity': 0,
                        'defaulted': 0,
                        'collecting': 0
                    },
                    'actor_oper_port_state': {
                        'distributing': 0,
                        'expired': 0,
                        'time_out': 1,
                        'aggregation': 1,
                        'sync': 0,
                        'lacp_activity': 1,
                        'defaulted': 1,
                        'collecting': 0
                    },
                    'lacp_control': {
                        'port_enabled': 0,
                        'partner_churn': 0,
                        'actor_churn': 0,
                        'selected': 0,
                        'ready_n': 0,
                        'ntt': 0,
                        'begin': 0,
                        'port_moved': 0
                    }
                },
                3: {
                    'partner_oper_port_state': {
                        'distributing': 0,
                        'expired': 0,
                        'time_out': 0,
                        'aggregation': 1,
                        'sync': 0,
                        'lacp_activity': 0,
                        'defaulted': 0,
                        'collecting': 0
                    },
                    'actor_oper_port_state': {
                        'distributing': 0,
                        'expired': 0,
                        'time_out': 1,
                        'aggregation': 1,
                        'sync': 0,
                        'lacp_activity': 1,
                        'defaulted': 1,
                        'collecting': 0
                    },
                    'lacp_control': {
                        'port_enabled': 0,
                        'partner_churn': 0,
                        'actor_churn': 0,
                        'selected': 0,
                        'ready_n': 0,
                        'ntt': 0,
                        'begin': 0,
                        'port_moved': 0
                    }
                },
                3-1: {
                    'partner_oper_port_state': {
                        'distributing': 0,
                        'expired': 0,
                        'time_out': 0,
                        'aggregation': 1,
                        'sync': 0,
                        'lacp_activity': 0,
                        'defaulted': 0,
                        'collecting': 0
                    },
                    'actor_oper_port_state': {
                        'distributing': 0,
                        'expired': 0,
                        'time_out': 1,
                        'aggregation': 1,
                        'sync': 0,
                        'lacp_activity': 1,
                        'defaulted': 1,
                        'collecting': 0
                    },
                    'lacp_control': {
                        'port_enabled': 0,
                        'partner_churn': 0,
                        'actor_churn': 0,
                        'selected': 0,
                        'ready_n': 0,
                        'ntt': 0,
                        'begin': 0,
                        'port_moved': 0
                    }
                }
            }
        },
        'Interfaces': {
            '10': {
                'eligible_interfaces': ['3', '2', '9-1'],
                'configured_interfaces': ['3', '2', '9-1'],
                'participant_interfaces': []
            }
        }
    }

    ddiff = DeepDiff(result, expected1)
    assert not ddiff


def test_parse_show_interface_loopback_brief():
    raw_result = """\
---------------------------------------------------
Loopback      IPv4 Address       Status
Interface
---------------------------------------------------

lo2         192.168.1.1/24      up
lo1024      192.168.2.1/24      up
     """  # noqa

    result = parse_show_interface_loopback_brief(raw_result)
    expected = [
        {
            'loopback_int': 'lo2',
            'loopback_ip': '192.168.1.1/24',
            'status': 'up'
        },
        {
            'loopback_int': 'lo1024',
            'loopback_ip': '192.168.2.1/24',
            'status': 'up'
        }
    ]

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_snmp_community():
    raw_result = """\
---------------------
SNMP communities
---------------------
public
private
community1
community2"""
    result = parse_show_snmp_community(raw_result)
    expected = ['public', 'private', 'community1', 'community2']
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_snmp_system():
    raw_result = """\
SNMP system information
-----------------------
System description : OpenSwitchsystem
System location : Bangalore
System contact :  xyz@id.com"""
    result = parse_show_snmp_system(raw_result)
    expected = {
        'system_description': 'OpenSwitchsystem',
        'system_location': 'Bangalore',
        'system_contact': 'xyz@id.com'
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_snmp_trap():
    raw_result = """\
------------------------------------------------------------------
Host              Port        Type           Version        SecName
-------------------------------------------------------------------
20.2.2.2          455         inform         v2c            testcom
10.1.1.1          162         trap           v1             public"""

    result = parse_show_snmp_trap(raw_result)
    expected = {
        '20.2.2.2': {
            'Port': '455',
            'Type': 'inform',
            'Version': 'v2c',
            'SecName': 'testcom'
        },
        '10.1.1.1': {
            'Port': '162',
            'Type': 'trap',
            'Version': 'v1',
            'SecName': 'public'
        }
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_snmpv3_users():
    raw_result = """\
--------------------------------------
User           AuthMode  PrivMode
--------------------------------------
user1          md5       des
user2          md5       (null)
user3          none      none"""

    result = parse_show_snmpv3_users(raw_result)
    expected = {
        'user1': {
            'AuthMode': 'md5',
            'PrivMode': 'des'
        },
        'user2': {
            'AuthMode': 'md5',
            'PrivMode': '(null)'
        },
        'user3': {
            'AuthMode': 'none',
            'PrivMode': 'none'
        }
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_diag_dump():

    raw_result = """\
=========================================================================
[Start] Feature lacp Time : Fri Apr 15 17:38:32 2016

=========================================================================
-------------------------------------------------------------------------
[Start] Daemon ops-lacpd
-------------------------------------------------------------------------
System Ports:
================ Ports ================
Port 5:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 5
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port bridge_normal:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : bridge_normal
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port 1:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 1
    eligible_members     :
    participant_members  :
    interface_count      : 0
Port lag10:
    lacp                 : active
    lag_member_speed     : 0
    configured_members   : 3 2
    eligible_members     : 3 2
    participant_members  :
    interface_count      : 0
Port 4:
    lacp                 : off
    lag_member_speed     : 0
    configured_members   : 4
    eligible_members     :
    participant_members  :
    interface_count      : 0

LAG interfaces: \nPort lag10:
    configured_members   : 3 2
    eligible_members     : 3 2
    participant_members  :

LACP PDUs counters: \nLAG lag10:
 Configured interfaces:
  Interface: 3
    lacp_pdus_sent: 0
    marker_response_pdus_sent: 0
    lacp_pdus_received: 0
    marker_pdus_received: 0
  Interface: 2
    lacp_pdus_sent: 0
    marker_response_pdus_sent: 0
    lacp_pdus_received: 0
    marker_pdus_received: 0

LACP state: \nLAG lag10:
 Configured interfaces:
  Interface: 3
    actor_oper_port_state \n\
        lacp_activity:1 time_out:1 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:1 expired:0
    partner_oper_port_state \n\
        lacp_activity:0 time_out:0 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:0 expired:0
    lacp_control
       begin:0 actor_churn:0 partner_churn:0 ready_n:0 selected:0 \
port_moved:0 ntt:0 port_enabled:0
  Interface: 2
    actor_oper_port_state \n\
       lacp_activity:1 time_out:1 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:1 expired:0
    partner_oper_port_state \n\
       lacp_activity:0 time_out:0 aggregation:1 sync:0 collecting:0 \
distributing:0 defaulted:0 expired:0
    lacp_control
       begin:0 actor_churn:0 partner_churn:0 ready_n:0 selected:0 \
port_moved:0 ntt:0 port_enabled:0 \n\

-------------------------------------------------------------------------
[End] Daemon ops-lacpd
-------------------------------------------------------------------------
-------------------------------------------------------------------------
[Start] Daemon ops-portd
-------------------------------------------------------------------------
Configuration file for lag10:
Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: load balancing (xor)
Transmit Hash Policy: layer2 (0)
MII Status: down
MII Polling Interval (ms): 0
Up Delay (ms): 0
Down Delay (ms): 0


-------------------------------------------------------------------------
[End] Daemon ops-portd
-------------------------------------------------------------------------
=========================================================================
[End] Feature lacp
=========================================================================
Diagnostic dump captured for feature lacp
    """
    result = parse_diag_dump(raw_result)

    expected = {
        'result': 0
    }

    ddiff = DeepDiff(result, expected)

    assert not ddiff


def test_parse_show_events():
    raw_result = """
2016-04-27:16:45:55.704265|ops-lacpd|15007|LOG_INFO|\
LACP system ID set to 70:72:cf:5b:fa:ae
2016-04-27:16:45:55.975889|ops-lldpd|1002|LOG_INFO|LLDP Disabled
    """

    expected_result = [
        {
            'date': '2016-04-27:16:45:55.704265',
            'daemon': 'ops-lacpd',
            'severity': 'LOG_INFO',
            'event_id': '15007',
            'message': 'LACP system ID set to 70:72:cf:5b:fa:ae'
        },
        {
            'date': '2016-04-27:16:45:55.975889',
            'daemon': 'ops-lldpd',
            'severity': 'LOG_INFO',
            'event_id': '1002',
            'message': 'LLDP Disabled'
        }
    ]

    result = parse_show_events(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff


def test_parse_show_spanning_tree_mst():
    raw_result = """\
#### MST0
Vlans mapped:  1
Bridge         Address:48:0f:cf:af:70:cf    priority:8
Operational    Hello time(in seconds): 2  Forward delay(in seconds):15  \
Max-age(in seconds):20  txHoldCount(in pps): 1
Configured     Hello time(in seconds): 2  Forward delay(in seconds):15  \
Max-age(in seconds):20  txHoldCount(in pps): 6

Port           Role           State      Cost       Priority   Type
-------------- -------------- ---------- ---------- ---------- ----------
1              Root           Forwarding 0          8          point_to_point
2              Alternate      Blocking   0          8          point_to_point
"""

    expected = {
        "MST0": {
            "vlan_mapped": "1",
            "2": {
                "role": "Alternate",
                "priority": "8",
                "type": "point_to_point",
                "State": "Blocking",
                "cost": "0"
            },
            "root": "no",
            "1": {
                "role": "Root",
                "priority": "8",
                "type": "point_to_point",
                "State": "Forwarding",
                "cost": "0"
            },
            "operational_forward_delay": "15",
            "operational_hello": "2",
            "Configuredl_forward_delay": "15",
            "Configured_tx_holdcount": "6",
            "bridge_address": "48:0f:cf:af:70:cf",
            "operational_tx_holdcount": "1",
            "operational_max_age": "20",
            "Configured_max_age": "20",
            "Configured_hello": "2",
            "regional_root": "no",
            "bridge_priority": "8"
        }
    }

    result = parse_show_spanning_tree_mst(raw_result)

    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_spanning_tree():
    raw_result = """\
MST0
  Spanning tree status: Enabled
  Root ID    Priority  : 8
             MAC-Address: 32768.0.48:0f:cf:af:20:51
             Hello time(in seconds):2  Max Age(in seconds):20  \
Forward Delay(in seconds):15

  Bridge ID  Priority  : 8
             MAC-Address: 48:0f:cf:af:40:57
             Hello time(in seconds):2  Max Age(in seconds):20  \
Forward Delay(in seconds):15

Port         Role           State      Cost    Priority   Type
------------ -------------- ---------- ------- ---------- ----------
2            Root           Forwarding 0       8          point_to_point
1            Designated     Forwarding 0       8          point_to_point
    """
    expected = {
        "root_hello": "2",
        "2": {
            "role": "Root",
            "priority": "8",
            "type": "point_to_point",
            "State": "Forwarding",
            "cost": "0"
        },
        "1": {
            "role": "Designated",
            "priority": "8",
            "type": "point_to_point",
            "State": "Forwarding",
            "cost": "0"
        },
        "bridge_max_age": "20",
        "root": "no",
        "root_priority": "8",
        "bridge_forward_delay": "15",
        "bridge_hello": "2",
        "bridge_priority": "8",
        "root_forward_delay": "15",
        "root_max_age": "20",
        "root_mac_address": "32768.0.48:0f:cf:af:20:51",
        "spanning_tree": "Enabled",
        "bridge_mac_address": "48:0f:cf:af:40:57"
    }
    result = parse_show_spanning_tree(raw_result)
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_spanning_tree_mst_config():
    raw_result = """ \
MST configuration information
   MST config ID        : Region-One
   MST config revision  : 8
   MST config digest    : AC36177F50283CD4B83821D8AB26DE62
   Number of instances  : 0

Instance ID     Member VLANs
--------------- ----------------------------------
    """
    expected = {
        "mst_config_revision": "8",
        "no_instances": "0",
        "instance_vlan": {},
        "mst_config_id": "Region-One",
        "mst_digest": "AC36177F50283CD4B83821D8AB26DE62"
    }

    result = parse_show_spanning_tree_mst_config(raw_result)
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_radius_server():
    raw_result = """
***** Radius Server information ******
Radius-server:1
 Host IP address        : 10.10.10.11
 Auth port              : 1812
 Shared secret          : procurve
 Retries                : 1
 Timeout                : 5
Radius-server:2
 Host IP address        : 10.10.10.12
 Auth port              : 1812
 Shared secret          : procurve
 Retries                : 1
 Timeout                : 5
    """

    expected_result = [
        {
            'radius_host_ip': '10.10.10.11',
            'radius_auth_port': '1812',
            'radius_shared_secret': 'procurve',
            'radius_retries': '1',
            'radius_timeout': '5'
        },
        {
            'radius_host_ip': '10.10.10.12',
            'radius_auth_port': '1812',
            'radius_shared_secret': 'procurve',
            'radius_retries': '1',
            'radius_timeout': '5'
        }
    ]

    result = parse_show_radius_server(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff


def test_parse_show_aaa_authentication():
    raw_result = """
AAA Authentication:
  Local authentication                  : Enabled
  Radius authentication                 : Disabled
  Fallback to local authentication      : Enabled
    """

    expected_result = {
        'local_auth_status': 'Enabled',
        'radius_auth_status': 'Disabled',
        'fallback_status': 'Enabled'
    }

    result = parse_show_aaa_authentication(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff


def test_parse_show_interface_brief():
    raw_result = """\

-------------------------------------------------------------------------------
Ethernet         VLAN    Type Mode   Status  Reason               Speed    Port
Interface                                                          (Mb/s)   Ch#
-------------------------------------------------------------------------------
 bridge_normal   --      eth  routed up                               --     --
 1               --      eth  routed down   Administratively down     --     --
 9-1             56      eth  access up                               10000  --

    """

    result = parse_show_interface_brief(raw_result)

    expected = {
        'bridge_normal': {
            'status': 'up',
            'type': ' eth',
            'vlanId': '--',
            'reason': None,
            'mode': 'routed',
            'interface': 'bridge_normal',
            'speed': '--',
            'port': '--'
        },
        '1': {
            'status': 'down',
            'type': ' eth',
            'vlanId': '--',
            'reason': 'Administratively down',
            'mode': 'routed',
            'interface': '1',
            'speed': '--',
            'port': '--'
        },
        '9-1': {
            'status': 'up',
            'type': ' eth',
            'vlanId': '56',
            'reason': None,
            'mode': 'access',
            'interface': '9-1',
            'speed': '10000',
            'port': '--'
        }
    }
    ddiff = DeepDiff(result, expected)
    assert not ddiff


def test_parse_show_vlan_summary():
    raw_result = """
Number of existing VLANs: 4
    """

    expected_result = {
        'vlan_count': '4'
    }

    result = parse_show_vlan_summary(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff


def test_parse_show_vlan_internal():
    raw_result = """
Internal VLAN range  : 1024-4094
Internal VLAN policy : ascending
------------------------
Assigned Interfaces:
        VLAN            Interface
        ----            ---------
        1024            1
        1025            10
    """

    expected_result = {
        '1024': {
            'vlan_id': '1024',
            'interface': '1'
        },
        '1025': {
            'vlan_id': '1025',
            'interface': '10'
        }
    }

    result = parse_show_vlan_internal(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff


def test_parse_show_access_list_hitcounts_ip_interface():
    raw_result = """\
Statistics for ACL test13 (ipv4):
Interface 2 (in):
           Hit Count  Configuration
                  10  50 permit any 10.0.10.1 10.0.10.2 count
    """

    expected_result = {
        '50 permit any 10.0.10.1 10.0.10.2 count': '10'
    }

    result = parse_show_access_list_hitcounts_ip_interface(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff


def test_parse_show_vrf():
    raw_result = """
VRF Configuration:
------------------
VRF Name : vrf_default

        Interfaces :     Status :
        -------------------------
        10                  up
        1                   up
        10-1                up
        1.14                up
        9-1.200             up
    """

    expected_result = {
        '10': {
            'interface': '10',
            'status': 'up'
        },
        '1': {
            'interface': '1',
            'status': 'up'
        },
        '10-1': {
            'interface': '10-1',
            'status': 'up'
        },
        '1.14': {
            'interface': '1.14',
            'status': 'up'
        },
        '9-1.200': {
            'interface': '9-1.200',
            'status': 'up'
        }
    }

    result = parse_show_vrf(raw_result)
    ddiff = DeepDiff(result, expected_result)

    assert not ddiff
