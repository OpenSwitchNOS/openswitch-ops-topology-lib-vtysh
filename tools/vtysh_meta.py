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
Vtysh meta-specification file.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from collections import OrderedDict


VTYSH_SPEC = OrderedDict([
    ('root', {
        'doc': '',
        'arguments': [],
        'pre_commands': [],
        'post_commands': [],
        'commands': [
            {
                'command': 'show interface {port}',
                'doc': 'Interface infomation.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
                'returns': True
            },
            {
                'command': 'show interface mgmt',
                'doc': 'Managment Interface infomation.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show interface {port} subinterface',
                'doc': 'Show subinterfaces configured on this interface',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
                'returns': True
            },
            {
                'command': 'show interface {port} subinterface brief',
                'doc': 'Show subinterface summary on a physical port',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
                'returns': True
            },
            {
                'command': 'show vlan',
                'doc': 'Show VLAN configuration.',
                'arguments': [
                    {
                        'name': 'vlanid',
                        'doc': 'Vlan ID number.',
                        'optional': True
                    }

                ],
                'returns': True
            },
            {
                'command': 'show lacp interface {port}',
                'doc': 'Show LACP interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    }
                ],
                'returns': True
            },
            {
                'command': 'show lacp aggregates',
                'doc': 'Show LACP aggregates.',
                'arguments': [
                    {
                        'name': 'lag',
                        'doc': 'Link-aggregate name.',
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show lacp configuration',
                'doc': 'Show LACP configuration.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show lldp neighbor-info {port}',
                'doc': 'Show global LLDP neighbor information.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show lldp statistics',
                'doc': 'Show LLDP statistics.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show sftp server',
                'doc': 'Show sftp server configuration.',
                'arguments': [],
                'returns': True

            },
            {
                'command': 'show ip bgp summary',
                'doc': 'Show bgp neighbors information summary.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip bgp neighbors',
                'doc': 'Show bgp neighbors information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip bgp',
                'doc': 'Show bgp routing information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ipv6 bgp',
                'doc': 'Show bgp routing information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ospf neighbor detail',
                'doc': 'Show ospf neighbor detail information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ospf neighbor',
                'doc': 'Show ospf neighbor information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ospf interface',
                'doc': 'Show ospf interface detail.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ospf',
                'doc': 'Show ospf detail.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ospf route',
                'doc': 'Show ospf detail.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show running-config',
                'doc': 'Show running-config information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip route',
                'doc': 'Show Routing Table.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ipv6 route',
                'doc': 'Display the routing table.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show sflow',
                'doc': 'Show sFlow information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show sflow interface {port}',
                'doc': 'Show sFlow information for the interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    }
                ],
                'returns': True
            },
            # TODO: Add support for the show udld (shows all interfaces) cmd
            {
                'command': 'show udld interface {port}',
                'doc': 'Show UDLD information for the interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
                'returns': True
            },
            {
                'command': 'show rib',
                'doc': 'Show Routing Information Base.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ip ecmp',
                'doc': 'Show ECMP Configuration',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'clear bgp {peer} {softreconfig}',
                'doc': 'Clear bgp peer.',
                'arguments': [
                    {
                        'name': 'peer',
                        'doc': 'BGP peer to clear.',
                    },
                    {
                        'name': 'softreconfig',
                        'doc': '<in | out | soft>',
                    },
                ],
            },
            {
                'command': 'clear udld statistics',
                'doc': 'Clear UDLD statistics from all interfaces.',
                'arguments': [],
            },
            {
                'command': 'clear udld statistics interface {port}',
                'doc': 'Clear UDLD statistics for the interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies interface.',
                    },
                ],
            },
            {
                'command': 'ping {destination} repetitions {count}',
                'doc': 'Send IPv4 ping',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<A.B.C.D> IPv4 address.'
                    },
                    {
                        'name': 'count',
                        'doc': 'Number of packets to send.'
                    }
                ],
                'returns': True
            },
            {
                'command': 'ping6 {destination} repetitions {count}',
                'doc': 'Send IPv6 ping',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<X:X::X:X> IPv6 address.'
                    },
                    {
                        'name': 'count',
                        'doc': 'Number of packets to send.'
                    }
                ],
                'returns': True
            },
            {
                'command': 'ping {destination}',
                'doc': 'Send IPv4 ping',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<A.B.C.D> IPv4 address.'
                    },
                    {
                        'name': 'count',
                        'doc': 'Number of packets to send.',
                        'prefix': 'repetitions ',
                        'optional': True
                    },
                    {
                        'name': 'size',
                        'doc': 'Size of packets to send.',
                        'prefix': 'datagram-size ',
                        'optional': True
                    },
                    {
                        'name': 'data',
                        'doc': 'Data to be filled in each packet.',
                        'prefix': 'data-fill ',
                        'optional': True
                    },
                    {
                        'name': 'interval',
                        'doc': 'Time interval between ping requests.',
                        'prefix': 'interval ',
                        'optional': True
                    },
                    {
                        'name': 'timeout',
                        'doc': 'Max time to wait for ping reply.',
                        'prefix': 'timeout ',
                        'optional': True
                    },
                    {
                        'name': 'tos',
                        'doc': (
                            'Type of service to be placed'
                            ' in each probe.'
                        ),
                        'prefix': 'tos ',
                        'optional': True
                    },
                    {
                        'name': 'ip_option',
                        'doc': 'Ip-option.',
                        'prefix': 'ip-option ',
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'ping6 {destination}',
                'doc': 'Send IPv6 ping',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<X:X::X:X> IPv6 address.'
                    },
                    {
                        'name': 'count',
                        'doc': 'Number of packets to send.',
                        'prefix': 'repetitions ',
                        'optional': True
                    },
                    {
                        'name': 'size',
                        'doc': 'Size of packets to send.',
                        'prefix': 'datagram-size ',
                        'optional': True
                    },
                    {
                        'name': 'data',
                        'doc': 'Data to be filled in each packet.',
                        'prefix': 'data-fill ',
                        'optional': True
                    },
                    {
                        'name': 'interval',
                        'doc': 'Time interval between ping requests.',
                        'prefix': 'interval ',
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'traceroute {destination}',
                'doc': 'Send IPv4 traceroute',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<A.B.C.D> IPv4 address.',
                    },
                    {
                        'name': 'min_ttl',
                        'doc': (
                            'Minimum number of hops to'
                            ' reach the destination <1-255>.'
                        ),
                        'prefix': 'minttl ',
                        'optional': True
                    },
                    {
                        'name': 'max_ttl',
                        'doc': (
                            'Maximum number of hops to'
                            ' reach the destination <1-255>.'
                        ),
                        'prefix': 'maxttl ',
                        'optional': True
                    },
                    {
                        'name': 'dst_port',
                        'doc': 'Destination port <1-34000>.',
                        'prefix': 'dstport ',
                        'optional': True
                    },
                    {
                        'name': 'time_out',
                        'doc': 'Traceroute timeout in seconds <1-60>.',
                        'prefix': 'timeout ',
                        'optional': True
                    },
                    {
                        'name': 'probes',
                        'doc': 'Number of Probes <1-5>.',
                        'prefix': 'probes ',
                        'optional': True
                    },
                    {
                        'name': 'ip_option_source',
                        'doc': 'Source for loose source route record.',
                        'prefix': 'ip-option loosesourceroute ',
                        'optional': True
                    }

                ],
                'returns': True
            },
            {
                'command': 'traceroute6 {destination}',
                'doc': 'Send IPv6 traceroute',
                'arguments': [
                    {
                        'name': 'destination',
                        'doc': '<X:X::X:X> IPv6 address.',
                    },
                    {
                        'name': 'max_ttl',
                        'doc': (
                            'Maximum number of hops to'
                            ' reach the destination <1-255>.'
                        ),
                        'prefix': 'maxttl ',
                        'optional': True
                    },
                    {
                        'name': 'dst_port',
                        'doc': 'Destination port <1-34000>.',
                        'prefix': 'dstport ',
                        'optional': True
                    },
                    {
                        'name': 'time_out',
                        'doc': 'Traceroute timeout in seconds <1-60>.',
                        'prefix': 'timeout ',
                        'optional': True
                    },
                    {
                        'name': 'probes',
                        'doc': 'Number of Probes <1-5>.',
                        'prefix': 'probes ',
                        'optional': True
                    }

                ],
                'returns': True

            },
            {
                'command': 'show ntp associations',
                'doc': 'Show NTP Association summary.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp authentication-key',
                'doc': 'Show NTP Authentication Keys information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp statistics',
                'doc': 'Show NTP Statistics information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp status',
                'doc': 'Show NTP Status information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show ntp trusted-keys',
                'doc': 'Show NTP Trusted Keys information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show dhcp-server leases',
                'doc': 'Show DHCP server leases information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show dhcp-server',
                'doc': 'Display DHCP server configuration.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show mac-address-table',
                'doc': 'Display L2 MAC address table information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show vlog config',
                'doc': 'Display vlog config.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show vlog {sub_command}',
                'doc': 'Show vlog sub command.',
                'arguments': [
                    {
                        'name': 'sub_command',
                        'doc': 'sub command'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show interface loopback',
                'doc': 'Show loopback interfaces on ops',
                'arguments': [
                    {
                        'name': 'loopback_int',
                        'doc': 'Loopback interface id.',
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show interface loopback brief',
                'doc': 'Display information for L3 loopback interfaces',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show vlog config daemon {daemon_name}',
                'doc': 'Display vlog config for ops-daemons.',
                'arguments': [
                    {
                        'name': 'daemon_name',
                        'doc': 'daemon name'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show vlog config feature {feature_name}',
                'doc': 'Display vlog config for feature',
                'arguments': [
                    {
                        'name': 'feature_name',
                        'doc': 'feature name'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show vlog config list',
                'doc': 'Display vlog config for supported features list',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show vlog daemon {daemon_name}',
                'doc': 'Display vlogs for ops-daemon',
                'arguments': [
                    {
                        'name': 'daemon_name',
                        'doc': 'daemon name'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show vlog severity {severity_level}',
                'doc': 'Display vlogs for severity level',
                'arguments': [
                    {
                        'name': 'severity_level',
                        'doc': 'severity level'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show vlog daemon {daemonname} severity {severity}',
                'doc': 'Display vlogs for ops-daemon with severity',
                'arguments': [
                    {
                        'name': 'daemonname',
                        'doc': 'daemon name'
                    },
                    {
                        'name': 'severity',
                        'doc': 'severity level'
                    }
                ],
                'returns': True
            },
            {
                'command': 'show vlog severity {severity} daemon {daemonname}',
                'doc': 'Display vlogs for severity with ops-daemon',
                'arguments': [
                    {
                        'name': 'severity',
                        'doc': 'severity level'
                    },
                    {
                        'name': 'daemonname',
                        'doc': 'daemon name'
                    }
                ],
                'returns': True
            },
            {
                'command': 'copy running-config startup-config',
                'doc': 'copies running config to startup config',
                'arguments': []
            },
            {
                'command': 'copy startup-config running-config',
                'doc': 'copies startup config to running config',
                'arguments': []
            },
            {
                'command': 'show startup-config',
                'doc': 'Show startup-config information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'erase startup-config',
                'doc': 'Erase startup-config information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show tftp-server',
                'doc': 'Display TFTP-Server configuration.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show mirror',
                'doc': 'Show mirroring session information.',
                'arguments': [
                    {
                        'name': 'name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        ),
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show qos cos-map',
                'doc': 'Shows the qos cos-map.',
                'arguments': [
                    {
                        'name': 'default',
                        'doc': 'Show the default cos-map.',
                        'optional': True
                    },
                ],
                'returns': True
            },
            {
                'command': 'show qos dscp-map',
                'doc': 'Shows the qos dscp-map.',
                'arguments': [
                    {
                        'name': 'default',
                        'doc': 'Show the default dscp-map.',
                        'optional': True
                    },
                ],
                'returns': True
            },
            {
                'command': 'show qos queue-profile',
                'doc': 'Shows the qos queue profile.',
                'arguments': [
                    {
                        'name': 'queue_profile_name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        ),
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show qos schedule-profile',
                'doc': 'Shows the qos schedule profile.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        ),
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show qos trust',
                'doc': 'Shows the qos trust.',
                'arguments': [
                    {
                        'name': 'default',
                        'doc': 'Show the default qos trust.',
                        'optional': True
                    },
                ],
                'returns': True
            },
            {
                'command': 'show snmp community',
                'doc': 'Display SNMP configured community names.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show snmp system',
                'doc': 'Display SNMP system information.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show snmp trap',
                'doc': 'Display SNMP host information of trap receivers.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'diag-dump lacp basic',
                'doc': 'Displays diagnostic information for LACP',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show snmpv3 users',
                'doc': 'Display SNMPV3 users.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show core-dump',
                'doc': 'Display core dumps present',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show snmp agent-port',
                'doc': 'Display SNMP agent port configuration.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show events',
                'doc': 'Show system related event logs.',
                'arguments': [
                    {
                        'name': 'filter',
                        'doc': 'Optional, filters by category,'
                               ' event-id or severity (filter value)',
                        'optional': True
                    }
                ],
                'returns': True
            },
            {
                'command': 'show aaa authentication',
                'doc': 'AAA authentication infomation.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'show radius-server',
                'doc': 'Radius Server infomation.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'diag-dump',
                'doc': 'Display diagnostics dump that supports diag-dump.',
                'arguments': [
                    {
                        'name': 'list',
                        'doc': (
                                'Optional, display daemons list '
                                'that are supporting the featured.'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'daemon',
                        'doc': (
                                'Optional, supported daemon name whose '
                                'diagnostics are to be requested.'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'level',
                        'doc': (
                                'Optional, takes the string values either '
                                'basic or advanced.'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'file',
                        'doc': (
                                'Optional, takes the string values either '
                                'filename where the output get dumped.'
                        ),
                        'optional': True
                    }
                ],
                'returns': True
            }
        ]
    }),
    ('configure', {
        'doc': 'Configuration terminal',
        'arguments': [],
        'pre_commands': ['configure terminal'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'no vlan {vlan_id}',
                'doc': 'Delete a VLAN',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': 'VLAN Identifier.',
                    },
                ],
            },
            {
                'command':
                'vlan internal range {min_range} {max_range} {order}',
                'doc': 'Set internal vlan range configuration <2-4094',
                'arguments': [
                    {
                        'name': 'min_range',
                        'doc': 'minimum vlan range for internal vlan is 2'
                    },
                    {
                        'name': 'max_range',
                        'doc': 'maximum vlan range for internal vlan is 4094'
                    },
                    {
                        'name': 'order',
                        'doc': 'Assign vlan in ascending(default) or \
                               descending order'
                    }



                ],
            },

            {
                'command': 'no interface lag {lag_id}',
                'doc': 'Delete a lag',
                'arguments': [
                    {
                        'name': 'lag_id',
                        'doc': 'link-aggregation identifier.',
                    },
                ],
            },
            {
                'command': 'no interface loopback {loopback_id}',
                'doc': 'Delete a L3 loopback interface',
                'arguments': [
                    {
                        'name': 'loopback_id',
                        'doc': 'Loopback interface identifier.',
                    },
                ],
            },
            {
                'command': 'session-timeout {mins}',
                'doc': 'Idle timeout range in minutes,0 disables the timeout',
                'arguments': [
                    {
                        'name': 'mins',
                        'doc': 'timeout in minutes',
                    },
                ],
            },
            {
                'command': 'no interface {port}.{subint}',
                'doc': 'Delete a subinterface',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Physical interface associated to subinterface',
                    },
                    {
                        'name': 'subint',
                        'doc': 'Subinterface ID',
                    },
                ],
            },
            {
                'command': 'ip route {ipv4} {next_hop}',
                'doc': 'Configure static routes',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no ip route {ipv4} {next_hop}',
                'doc': 'Un-configure static routes',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': (
                    'ip prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Configure prefix list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  Name of a prefix list.',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number.',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'A.B.C.D/M  IP prefix <network>/<length>, e.g., '
                            '35.0.0.0/8 any Any prefix match. Same as '
                            '"0.0.0.0/0 le 32"'
                        ),
                    },
                ],
            },
            {
                'command': (
                    'no ip prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Un-configure prefix list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  Name of a prefix list.',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number.',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'A.B.C.D/M  IP prefix <network>/<length>, e.g., '
                            '35.0.0.0/8 any Any prefix match. Same as '
                            '"0.0.0.0/0 le 32"'
                        ),
                    },
                ],
            },
            {
                'command': (
                    'ipv6 prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Configure IPv6 prefix-based filtering',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  The IP prefix-list name',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'X:X::X:X/M IPv6 prefix'
                        ),
                    },
                ],
            },
            {
                'command': (
                    'no ipv6 prefix-list {prefix_name} seq {seq}'
                    ' {permission} {network}'
                ),
                'doc': 'Deletes the IPv6 prefix-list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  The IP prefix-list name',
                    },
                    {
                        'name': 'seq',
                        'doc': '<1-4294967295>  Sequence number',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny    Specify packets to reject'
                            'permit  Specify packets to forward'
                        ),
                    },
                    {
                        'name': 'network',
                        'doc': (
                            'X:X::X:X/M IPv6 prefix'
                        ),
                    },
                ],
            },
            {
                'command': 'no route-map {routemap_name} {permission} {seq}',
                'doc': 'Route-map configuration',
                'arguments': [
                    {
                        'name': 'routemap_name',
                        'doc': 'WORD  Route map tag',
                    },
                    {
                        'name': 'permission',
                        'doc': (
                            'deny  Route map denies set operations'
                            'permit  Route map permits set operations'
                        ),
                    },
                    {
                        'name': 'seq',
                        'doc': (
                            '<1-65535>  Sequence to insert to/delete from '
                            'existing route-map entry'
                        ),
                    },
                ],
            },
            {
                'command': 'ipv6 route {ipv6} {next_hop}',
                'doc': 'Configure static routes',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no ipv6 route {ipv6} {next_hop}',
                'doc': 'Un-configure static routes',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M IP destination prefix.',
                    },
                    {
                        'name': 'next_hop',
                        'doc': 'Can be an ip address or a interface.',
                    },
                    {
                        'name': 'metric',
                        'doc': 'Optional, route address to configure.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'apply qos queue-profile {queue_profile_name} \
schedule-profile {schedule_profile_name}',
                'doc': 'Applies qos profiles.',
                'arguments': [
                    {
                        'name': 'queue_profile_name',
                        'doc': 'The queue profile to apply.',
                    },
                    {
                        'name': 'schedule_profile_name',
                        'doc': 'The schedule profile to apply.',
                    },
                ],
            },
            {
                'command': 'qos cos-map {code_point} \
local-priority {local_priority}',
                'doc': 'Configures the qos cos-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the cos map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the cos map entry.',
                    },
                ],
            },
            {
                'command': 'qos cos-map {code_point} \
local-priority {local_priority} color {color}',
                'doc': 'Configures the qos cos-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the cos map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the cos map entry.',
                    },
                    {
                        'name': 'color',
                        'doc': 'The color of the cos map entry.',
                    },
                ],
            },
            {
                'command': 'qos cos-map {code_point} \
local-priority {local_priority} name {name}',
                'doc': 'Configures the qos cos-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the cos map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the cos map entry.',
                    },
                    {
                        'name': 'name',
                        'doc': 'The name of the cos map entry.',
                    },
                ],
            },
            {
                'command': 'qos cos-map {code_point} \
local-priority {local_priority} color {color} name {name}',
                'doc': 'Configures the qos cos-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the cos map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the cos map entry.',
                    },
                    {
                        'name': 'color',
                        'doc': 'The color of the cos map entry.',
                    },
                    {
                        'name': 'name',
                        'doc': 'The name of the cos map entry.',
                    },
                ],
            },
            {
                'command': 'qos cos-map {code_point} \
local-priority {local_priority} name {name} color {color}',
                'doc': 'Configures the qos cos-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the cos map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the cos map entry.',
                    },
                    {
                        'name': 'name',
                        'doc': 'The name of the cos map entry.',
                    },
                    {
                        'name': 'color',
                        'doc': 'The color of the cos map entry.',
                    },
                ],
            },
            {
                'command': 'no qos cos-map {code_point}',
                'doc': 'Restores a qos cos-map entry to factory default.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the cos map entry.',
                    },
                ],
            },
            {
                'command': 'qos dscp-map {code_point} \
local-priority {local_priority}',
                'doc': 'Configures the qos dscp-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the dscp map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the dscp map entry.',
                    },
                ],
            },
            {
                'command': 'qos dscp-map {code_point} \
local-priority {local_priority} color {color}',
                'doc': 'Configures the qos dscp-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the dscp map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the dscp map entry.',
                    },
                    {
                        'name': 'color',
                        'doc': 'The color of the dscp map entry.',
                    },
                ],
            },
            {
                'command': 'qos dscp-map {code_point} \
local-priority {local_priority} name {name}',
                'doc': 'Configures the qos dscp-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the dscp map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the dscp map entry.',
                    },
                    {
                        'name': 'name',
                        'doc': 'The name of the dscp map entry.',
                    },
                ],
            },
            {
                'command': 'qos dscp-map {code_point} \
local-priority {local_priority} color {color} name {name}',
                'doc': 'Configures the qos dscp-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the dscp map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the dscp map entry.',
                    },
                    {
                        'name': 'color',
                        'doc': 'The color of the dscp map entry.',
                    },
                    {
                        'name': 'name',
                        'doc': 'The name of the dscp map entry.',
                    },
                ],
            },
            {
                'command': 'qos dscp-map {code_point} \
local-priority {local_priority} name {name} color {color}',
                'doc': 'Configures the qos dscp-map.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the dscp map entry.',
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority of the dscp map entry.',
                    },
                    {
                        'name': 'name',
                        'doc': 'The name of the dscp map entry.',
                    },
                    {
                        'name': 'color',
                        'doc': 'The color of the dscp map entry.',
                    },
                ],
            },
            {
                'command': 'no qos dscp-map {code_point}',
                'doc': 'Restores a qos dscp-map entry to factory default.',
                'arguments': [
                    {
                        'name': 'code_point',
                        'doc': 'The code point of the dscp map entry.',
                    },
                ],
            },
            {
                'command': 'qos queue-profile {queue_profile_name}',
                'doc': 'Creates a queue profile.',
                'arguments': [
                    {
                        'name': 'queue_profile_name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        )
                    }
                ]
            },
            {
                'command': 'no qos queue-profile {queue_profile_name}',
                'doc': 'Deletes a queue profile.',
                'arguments': [
                    {
                        'name': 'queue_profile_name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        )
                    }
                ]
            },
            {
                'command': 'qos schedule-profile {schedule_profile_name}',
                'doc': 'Creates a schedule profile.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        )
                    }
                ]
            },
            {
                'command': 'no qos schedule-profile {schedule_profile_name}',
                'doc': 'Deletes a schedule profile.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        )
                    }
                ]
            },
            {
                'command': 'qos trust {value}',
                'doc': 'Sets qos trust.',
                'arguments': [
                    {
                        'name': 'value',
                        'doc': 'none, cos, or dscp',
                    },
                ],
            },
            {
                'command': 'no qos trust',
                'doc': 'Restores qos trust to its factory default.',
                'arguments': [],
            },
            {
                'command': 'lacp system-priority {priority}',
                'doc': 'Set LACP system priority.',
                'arguments': [
                    {
                        'name': 'priority',
                        'doc': '<0-65535>  The range is 0 to 65535.',
                    },
                ],
            },
            {
                'command': 'lldp enable',
                'doc': 'Enable LLDP globally.',
                'arguments': [],
            },
            {
                'command': 'no lldp enable',
                'doc': 'Disable LLDP globally.',
                'arguments': [],
            },
            {
                'command': 'lldp clear {param}',
                'doc': 'Clear LLDP counters and neighbors.',
                'arguments': [
                    {
                        'name': 'param',
                                'doc': (
                                    'counters clear lldp counters'
                                    'neighbors clear lldp neighbors'
                                ),
                    },
                ],
            },
            {
                'command': 'lldp holdtime {holdtime_multiplier}',
                'doc': 'Configure hold time multiplier.',
                'arguments': [
                    {
                        'name': 'holdtime_multiplier',
                        'doc': '<5-32768>  holdtime_multiplier range',
                    }
                ],
            },
            {
                'command': 'no lldp holdtime {holdtime_multiplier}',
                'doc': 'Unconfigure hold time multiplier.',
                'arguments': [
                    {
                        'name': 'holdtime_multiplier',
                        'doc': '<5-32768>  holdtime_multiplier range',
                    }
                ],
            },
            {
                'command': 'lldp management-address {lldp_mgmt_address}',
                'doc': 'Configure LLDP management IPV4/IPV6 address.',
                'arguments': [
                    {
                        'name': 'lldp_mgmt_address',
                        'doc': 'A.B.C.D/X:X::X:X IPV4/IPV6 address.',
                    }
                ],
            },
            {
                'command': 'no lldp management-address {lldp_mgmt_address}',
                'doc': 'Unconfigure LLDP management IPV4/IPV6 address.',
                'arguments': [
                    {
                        'name': 'lldp_mgmt_address',
                        'doc': 'A.B.C.D/X:X::X:X IPV4/IPV6 address.',
                    }
                ],
            },
            {
                'command': 'lldp reinit {reinit_timer}',
                'doc': 'Configure wait time before LLDP initialization.',
                'arguments': [
                    {
                        'name': 'reinit_timer',
                        'doc': '<1-10>  reinit_timer range',
                    }
                ],
            },
            {
                'command': 'no lldp reinit {reinit_timer}',
                'doc': 'Unconfigure wait time before LLDP initialization.',
                'arguments': [
                    {
                        'name': 'reinit_timer',
                        'doc': '<1-10>  reinit_timer range',
                    }
                ],
            },
            {
                'command': 'lldp select-tlv {tlv_field}',
                'doc': 'Enabling LLDP tlv field management IP address.',
                'arguments': [
                    {
                        'name': 'tlv_field',
                        'doc': (
                            'management-address Enable management-address'
                            'port-description Enable port-description'
                            'port-protocol-id Enable port-protocol-id'
                            'port-protocol-vlan-id Enable \
                            port-protocol-vlan-id'
                            'port-vlan-id Enable port-vlan-id'
                            'port-vlan-name Enable port-vlan-name'
                            'system-capabilities Enable system-capabilities'
                            'system-description Enable system-description'
                            'system-name Enable system-name'
                        ),
                    },
                ],
            },
            {
                'command': 'no lldp select-tlv {tlv_field}',
                'doc': 'Enabling LLDP tlv field management IP address.',
                'arguments': [
                    {
                        'name': 'tlv_field',
                        'doc': (
                            'management-address Enable management-address'
                            'port-description Enable port-description'
                            'port-protocol-id Enable port-protocol-id'
                            'port-protocol-vlan-id Enable \
                            port-protocol-vlan-id'
                            'port-vlan-id Enable port-vlan-id'
                            'port-vlan-name Enable port-vlan-name'
                            'system-capabilities Enable system-capabilities'
                            'system-description Enable system-description'
                            'system-name Enable system-name'
                        ),
                    },
                ],
            },

            {
                'command': 'lldp timer {lldp_update_timer}',
                'doc': 'Configure LLDP status update interval.',
                'arguments': [
                    {
                        'name': 'lldp_update_timer',
                        'doc': '<5-32768>  lldp_update_timer range',
                    }
                ],
            },
            {
                'command': 'no lldp timer {lldp_update_timer}',
                'doc': 'Unconfigure LLDP status update interval.',
                'arguments': [
                    {
                        'name': 'lldp_update_timer',
                        'doc': '<5-32768>  lldp_update_timer range',
                    }
                ],
            },
            {
                'command': 'sflow enable',
                'doc': 'Configure sFlow.',
                'arguments': [],
            },
            {
                'command': 'no sflow enable',
                'doc': 'Un-configure sFlow.',
                'arguments': [],
            },
            {
                'command': 'sflow sampling {rate}',
                'doc': 'Set sFlow sampling rate.',
                'arguments': [
                    {
                        'name': 'rate',
                        'doc': '<1-1000000000>  The range is 1 to 1000000000.',
                    }
                ],
            },
            {
                'command': 'sflow header-size {size}',
                'doc': 'Set sFlow header-size size.',
                'arguments': [
                    {
                        'name': 'size',
                        'doc': '<64-256>  The size is 64 to 256.',
                    }
                ],
            },
            {
                'command': 'no sflow header-size',
                'doc': 'Unset sFlow header-size',
                'arguments': [],
            },
            {
                'command': 'sflow max-datagram-size {size}',
                'doc': 'Set sFlow max-datagram-size size.',
                'arguments': [
                    {
                        'name': 'size',
                        'doc': '<1-9000>  The size is 1 to 9000.',
                    }
                ],
            },
            {
                'command': 'no sflow max-datagram-size',
                'doc': 'Unset sFlow max-datagram-size',
                'arguments': [],
            },
            {
                'command': 'no sflow sampling',
                'doc': 'Reset sFlow sampling rate to default.',
                'arguments': [],
            },
            {
                'command': 'sflow polling {interval}',
                'doc': 'Set sFlow polling interval.',
                'arguments': [
                    {
                        'name': 'interval',
                        'doc': '<0-3600>  The range is 0 to 3600.',
                    }
                ],
            },
            {
                'command': 'no sflow polling',
                'doc': 'Reset sFlow polling interval to default.',
                'arguments': [],
            },
            {
                'command': (
                    'sflow agent-interface {portlbl}'
                ),
                'doc': 'Set sFlow agent interface',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Valid L3 interface name.',
                    },
                    {
                        'name': 'address_family',
                        'doc': 'Optional, IPv4 or IPv6 (Default : IPv4).',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'no sflow agent-interface',
                'doc': 'Remove sFlow agent interface configuration.',
                'arguments': [],
            },
            {
                'command': 'sflow collector {ip}',
                'doc': 'Set sFlow collector configuration (IP)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    }
                ],
            },
            {
                'command': 'sflow collector {ip} port {port}',
                'doc': 'Set sFlow collector configuration (IP, port)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    },
                    {
                        'name': 'port',
                        'doc': 'Port of collector <0-65535> (Default : 6343).',
                    }
                ],
            },
            {
                'command': 'sflow collector {ip} vrf {vrf}',
                'doc': 'Set sFlow collector configuration (IP, vrf)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    },
                    {
                        'name': 'vrf',
                        'doc': 'Name of VRF (Default : vrf_default).',
                    }
                ],
            },
            {
                'command': 'sflow collector {ip} port {port} vrf {vrf}',
                'doc': 'Set sFlow collector configuration (IP, port, vrf)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'IP address of collector.',
                    },
                    {
                        'name': 'port',
                        'doc': 'Port of collector <0-65535> (Default : 6343).',
                    },
                    {
                        'name': 'vrf',
                        'doc': 'Name of VRF (Default : vrf_default).',
                    }
                ],
            },
            {
                'command': 'no router bgp {asn}',
                'doc': 'Removes the BGP Router',
                'arguments': [
                    {
                        'name': 'asn',
                        'doc': 'Autonomous System Number.',
                    }
                ],
            },
            {
                'command': 'no router ospf',
                'doc': 'Removes the OSPF Router',
                'arguments': [],
            },
            {
                'command': 'ip ecmp disable',
                'doc': 'Completely disable ECMP',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp disable',
                'doc': 'Completely disable ECMP',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance dst-ip disable',
                'doc': 'Disable load balancing by destination IP',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance dst-ip disable',
                'doc': 'Disable load balancing by destination IP',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance dst-port disable',
                'doc': 'Disable load balancing by destination port',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance dst-port disable',
                'doc': 'Disable load balancing by destination port',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance src-port disable',
                'doc': 'Disable load balancing by source port',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance src-port disable',
                'doc': 'Disable load balancing by source port',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance src-ip disable',
                'doc': 'Disable load balancing by source IP',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance src-ip disable',
                'doc': 'Disable load balancing by source IP',
                'arguments': [],
            },
            {
                'command': 'ip ecmp load-balance resilient disable',
                'doc': 'Disable resilient hashing for load balancing',
                'arguments': [],
            },
            {
                'command': 'no ip ecmp load-balance resilient disable',
                'doc': 'Disable resilient hashing for load balancing',
                'arguments': [],
            },
            {
                'command': 'sftp server enable',
                'doc': 'Enable sftp server.',
                'arguments': [],
            },
            {
                'command': 'no sftp server enable',
                'doc': 'Disable sftp server.',
                'arguments': [],
            },
            {
                'command': 'ntp server {host}',
                'doc': 'NTP Association configuration',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    }
                ],
            },
            {
                'command': 'no ntp server {host}',
                'doc': 'Remove NTP association',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    }
                ],
            },
            {
                'command': 'ntp server {host} prefer',
                'doc': 'Add NTP Association preference configuration',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    }
                ],
            },
            {
                'command': 'ntp server {host} key-id {key_id}',
                'doc': 'Add NTP Key ID',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    },
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'ntp server {host} version {version}',
                'doc': 'Add NTP Association version configuration',
                'arguments': [
                    {
                        'name': 'host',
                        'doc': 'NTP Association name or IPv4 Address.',
                    },
                    {
                        'name': 'version',
                        'doc': 'WORD  Version can be 3 or 4',
                    }
                ],
            },
            {
                'command': 'ntp authentication enable',
                'doc': 'Enable NTP Authentication configuration',
                'arguments': [],
            },
            {
                'command': 'no ntp authentication enable',
                'doc': 'Disable NTP Authentication configuration',
                'arguments': [],
            },
            {
                'command': 'ntp authentication-key {key_id} md5 {password}',
                'doc': 'Add NTP Authentication Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    },
                    {
                        'name': 'password',
                        'doc': 'WORD  NTP MD5 Password <8-16> chars',
                    }
                ],
            },
            {
                'command': 'no ntp authentication-key {key_id}',
                'doc': 'Remove NTP Authentication Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'ntp trusted-key {key_id}',
                'doc': 'Add NTP Trusted Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'no ntp trusted-key {key_id}',
                'doc': 'Remove NTP Trusted Key',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': 'WORD  NTP Key Number between 1-65534',
                    }
                ],
            },
            {
                'command': 'logging {remote_host}',
                'doc': 'Configure Syslog Server',
                'arguments': [
                    {
                        'name': 'remote_host',
                        'doc': 'IPv4 or IPv6 or Host name of syslog server',
                    },
                    {
                        'name': 'transport',
                        'doc': (
                            'Optional : '
                            'Transport protocol and port used to send syslog.'
                            '  Currently we support only tcp and udp.  '
                            'Example tcp 1049'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'severity',
                        'doc': (
                            'Optional : '
                            'Filter syslog messages using severity.'
                            '  Only messages with severity higher than or'
                            ' equal to the specified severity will be sent'
                            ' to the remote host.  '
                            'Example severity debug'
                        ),
                        'optional': True
                    }
                ],
            },
            {
                'command': 'no logging {remote_host}',
                'doc': 'Remove Syslog Server Configuration',
                'arguments': [
                    {
                        'name': 'remote_host',
                        'doc': 'IPv4 or IPv6 or Host name of syslog server',
                    },
                    {
                        'name': 'transport',
                        'doc': (
                            'Optional : '
                            'Transport protocol and port used to send syslog. '
                            '  Currently we support only tcp and udp.  '
                            'Example tcp 1049'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'severity',
                        'doc': (
                            'Optional : '
                            'Filter syslog messages using severity.'
                            '  Only messages with severity higher than or'
                            ' equal to the specified severity will be sent'
                            ' to the remote host.  '
                            'Example severity debug'
                        ),
                        'optional': True
                    }

                ],
            },
            {
                'command': 'vlog daemon {daemon} {destination} {severity}',
                'doc': 'Configure the daemon',
                'arguments': [
                    {
                        'name': 'daemon',
                        'doc': 'daemon name',
                    },
                    {
                        'name': 'destination',
                        'doc': 'configure the log level of destination',
                    },
                    {
                        'name': 'severity',
                        'doc': 'severity level'
                    }
                ],
            },
            {
                'command': 'vlog feature {feature} {destination} {severity}',
                'doc': 'Configure the feature',
                'arguments': [
                    {
                        'name': 'feature',
                        'doc': 'feature name',
                    },
                    {
                        'name': 'destination',
                        'doc': 'configure the log level of destination',
                    },
                    {
                        'name': 'severity',
                        'doc': 'severity level'
                    }
                ],
            },
            {
                'command': 'logrotate period {time_interval}',
                'doc': 'Set Logrotate time interval.',
                'arguments': [
                    {
                        'name': 'time_interval',
                        'doc': 'rotates log files time interval',
                    },
                ],
            },
            {
                'command': 'logrotate maxsize {file_size}',
                'doc': 'Set Logrotate maxsize of file.',
                'arguments': [
                    {
                        'name': 'file_size',
                        'doc': '<1-200>  File size in Mega Bytes',
                    },
                ],
            },
            {
                'command': 'logrotate target {tftp_host}',
                'doc': 'Set Logrotate tftp remote host.',
                'arguments': [
                    {
                        'name': 'tftp_host',
                        'doc': 'URI of the remote host',
                    },
                ],
            },
            {
                'command': 'snmp-server community {community_name}',
                'doc': 'Configure SNMP community names',
                'arguments': [
                    {
                        'name': 'community_name',
                        'doc': 'Configured Community names'
                    }
                ],
            },
            {
                'command': 'no snmp-server community',
                'doc': 'Unconfigure SNMP community names',
                'arguments': [
                    {
                        'name': 'community_name',
                        'doc': 'Unconfigured community names',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'snmp-server system-contact {system_contact}',
                'doc': 'Configure SNMP system contact information',
                'arguments': [
                    {
                        'name': 'system_contact',
                        'doc': 'Configured System contact information'
                    }
                ],
            },
            {
                'command': 'no snmp-server system-contact',
                'doc': 'Unconfigure SNMP contact information',
                'arguments': [
                    {
                        'name': 'system_contact',
                        'doc': 'Unconfigure system contact information',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'snmp-server system-location {system_location}',
                'doc': 'Configure SNMP system location information',
                'arguments': [
                    {
                        'name': 'system_location',
                        'doc': 'Configured System location information'
                    }
                ],
            },
            {
                'command': 'no snmp-server system-location',
                'doc': 'Unconfigure SNMP location information',
                'arguments': [
                    {
                        'name': 'system_location',
                        'doc': 'Unconfigure system location information',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'snmp-server system-description\
                {system_description}',
                'doc': 'Configure SNMP system description',
                'arguments': [
                    {
                        'name': 'system_description',
                        'doc': 'Configured System description'
                    }
                ],
            },
            {
                'command': 'no snmp-server system-description',
                'doc': 'Unconfigure SNMP system description',
                'arguments': [
                    {
                        'name': 'system_desription',
                        'doc': 'Unconfigure system description',
                        'optional': True
                    }
                ],
            },
            {
                'command': ('snmp-server host {host_ip_address} trap version '
                            '{snmp_version}'),
                'doc': 'Configure SNMP server information for trap receiver',
                'arguments': [
                    {
                        'name': 'host_ip_address',
                        'doc': 'Configured host ip address for trap receiver'
                    },
                    {
                        'name': 'snmp_version',
                        'doc': 'Configured snmp version for receiver'
                    },
                    {
                        'name': 'community',
                        'doc': 'Configured snmp community name for trap \
                                receiver',
                        'optional': True
                    },
                    {
                        'name': 'community_name',
                        'doc': 'Configured snmp community name for trap \
                                receiver',
                        'optional': True
                    },
                    {
                        'name': 'port',
                        'doc': 'Configured snmp port for trap receiver',
                        'optional': True
                    },
                    {
                        'name': 'snmp_port',
                        'doc': 'Configured snmp port for trap receiver',
                        'optional': True
                    }
                ],
            },
            {
                'command': ('no snmp-server host {host_ip_address} trap '
                            'version {snmp_version}'),
                'doc': 'Unconfigure SNMP server information for trap receiver',
                'arguments': [
                    {
                        'name': 'host_ip_address',
                        'doc': 'Unconfigured host ip address for trap \
                                receiver'
                    },
                    {
                        'name': 'snmp_version',
                        'doc': 'Unconfigured snmp version for receiver'
                    },
                    {
                        'name': 'community',
                        'doc': 'Unconfigured snmp community name for trap \
                                receiver',
                        'optional': True
                    },
                    {
                        'name': 'community_name',
                        'doc': 'Unconfigured snmp community name for trap \
                                receiver',
                        'optional': True
                    },
                    {
                        'name': 'port',
                        'doc': 'Unconfigured snmp port for trap receiver',
                        'optional': True
                    },
                    {
                        'name': 'snmp_port',
                        'doc': 'Unconfigured snmp port for trap receiver',
                        'optional': True
                    }
                ],
            },
            {
                'command': ('snmp-server host {host_ip_address} inform '
                            'version {snmp_version}'),
                'doc': 'Configure SNMP server information for notifications',
                'arguments': [
                    {
                        'name': 'host_ip_address',
                        'doc': 'Configured host ip address for notifications'
                    },
                    {
                        'name': 'snmp_version',
                        'doc': 'Configured snmp version for notifications'
                    },
                    {
                        'name': 'community',
                        'doc': 'Configured snmp community name for \
                                notifications',
                        'optional': True
                    },
                    {
                        'name': 'community_name',
                        'doc': 'Configured snmp community name for \
                                notifications',
                        'optional': True
                    },
                    {
                        'name': 'port',
                        'doc': 'Configured snmp port for notifications',
                        'optional': True
                    },
                    {
                        'name': 'snmp_port',
                        'doc': 'Configured snmp port for notifications',
                        'optional': True
                    }
                ],
            },
            {
                'command': ('no snmp-server host {host_ip_address} inform '
                            'version {snmp_version}'),
                'doc': 'Unconfigure SNMP server information for notifications',
                'arguments': [
                    {
                        'name': 'host_ip_address',
                        'doc': 'Unconfigured host ip address for \
                                notifications'
                    },
                    {
                        'name': 'snmp_version',
                        'doc': 'Unconfigured snmp version for notifications'
                    },
                    {
                        'name': 'community',
                        'doc': 'Unconfigured snmp community name for \
                                notifications',
                        'optional': True
                    },
                    {
                        'name': 'community_name',
                        'doc': 'Unconfigured snmp community name for \
                                notifications',
                        'optional': True
                    },
                    {
                        'name': 'port',
                        'doc': 'Unconfigured snmp port for notifications',
                        'optional': True
                    },
                    {
                        'name': 'snmp_port',
                        'doc': 'Unconfigured snmp port for notifications',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'snmpv3 user {user_name}',
                'doc': 'Configure SNMPv3 user name',
                'arguments': [
                    {
                        'name': 'user-name',
                        'doc': 'Configured user_name for SNMPv3'
                    }
                ],
            },
            {
                'command': 'no snmpv3 user {user_name}',
                'doc': 'Unconfigure SNMPv3 user name',
                'arguments': [
                    {
                        'name': 'user_name',
                        'doc': 'Unconfigured SNMPv3 user name'
                    }
                ],
            },
            {
                'command': ('snmpv3 user {user_name} auth {auth_protocol} '
                            'auth-pass {auth_password}'),
                'doc': 'Configure SNMPv3 user name with auth protocol and \
                        password',
                'arguments': [
                    {
                        'name': 'user_name',
                        'doc': 'Configured user-name for SNMPv3'
                    },
                    {
                        'name': 'auth_protocol',
                        'doc': 'Configured auth protocol for SNMPv3 user'
                    },
                    {
                        'name': 'auth_password',
                        'doc': 'Configured auth password for SNMPv3 user'
                    }

                ],
            },
            {
                'command': ('no snmpv3 user {user_name} auth {auth_protocol} '
                            'auth-pass {auth_password}'),
                'doc': 'Unconfigure SNMPv3 user name with auth protocol and \
                        password',
                'arguments': [
                    {
                        'name': 'user_name',
                        'doc': 'Unconfigured user-name for SNMPv3'
                    },
                    {
                        'name': 'auth_protocol',
                        'doc': 'Unconfigured auth protocol for SNMPv3 user'
                    },
                    {
                        'name': 'auth_password',
                        'doc': 'Unconfigured auth password for SNMPv3 user'
                    }

                ],
            },
            {
                'command': ('snmpv3 user {user_name} auth {auth_protocol} '
                            'auth-pass {auth_password} priv {priv_protocol} '
                            'priv-pass {priv_password}'),
                'doc': 'Configure SNMPv3 user name with auth protocol and \
                        password',
                'arguments': [
                    {
                        'name': 'user_name',
                        'doc': 'Configured user-name for SNMPv3'
                    },
                    {
                        'name': 'auth_protocol',
                        'doc': 'Configured auth protocol for SNMPv3 user'
                    },
                    {
                        'name': 'auth_password',
                        'doc': 'Configured auth password for SNMPv3 user'
                    },
                    {
                        'name': 'priv_protocol',
                        'doc': 'Configured priv protocol for SNMPv3 user'
                    },
                    {
                        'name': 'priv_password',
                        'doc': 'Configured priv password for SNMPv3 user'
                    }

                ],
            },
            {
                'command': ('no snmpv3 user {user_name} auth {auth_protocol} '
                            'auth-pass {auth_password} priv {priv_protocol} '
                            'priv-pass {priv_password}'),
                'doc': 'Unconfigure SNMPv3 user name with auth protocol and \
                        password',
                'arguments': [
                    {
                        'name': 'user_name',
                        'doc': 'Unconfigured user-name for SNMPv3'
                    },
                    {
                        'name': 'auth_protocol',
                        'doc': 'Unconfigured auth protocol for SNMPv3 user'
                    },
                    {
                        'name': 'auth_password',
                        'doc': 'Unconfigured auth password for SNMPv3 user'
                    },
                    {
                        'name': 'priv_protocol',
                        'doc': 'Unconfigured priv protocol for SNMPv3 user'
                    },
                    {
                        'name': 'priv_password',
                        'doc': 'Unconfigured priv password for SNMPv3 user'
                    }

                ],
            },
            {
                'command': 'snmp-server agent-port {port_num}',
                'doc': 'Configure SNMP agent port',
                'arguments': [
                    {
                       'name': 'port_num',
                       'doc': 'UDP port on which the SNMP agent listens'
                    }
                ],
            },
            {
                'command': 'no snmp-server agent-port',
                'doc': 'Unconfigure SNMP agent port',
                'arguments': [
                    {
                        'name': 'port_num',
                        'doc': 'UDP port on which the SNMP agent listens',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'no mirror session {name}',
                'doc': 'Delete a mirroring session.',
                'arguments': [
                    {
                        'name': 'name',
                        'doc': (
                            'Up to 64 letters, numbers, underscores, dashes, '
                            'or periods.'
                        )
                    }
                ]
            },
            {
                'command': 'access-list ip {access_list}',
                'doc': 'Configure access list.',
                'arguments': [
                    {
                        'name': 'access_list',
                        'doc': 'Access List Name.',
                    },
                ],
            },
            {
                'command': 'no access-list ip {access_list}',
                'doc': 'Unconfigure access list.',
                'arguments': [
                    {
                        'name': 'access_list',
                        'doc': 'Access List Name.',
                    },
                ],
            },
            {
                'command': 'access-list ip {access_list} resequence'
                           ' {start} {increment}',
                'doc': 'Resequence ACL Lists.',
                'arguments': [
                    {
                        'name': 'access_list',
                        'doc': 'Access List Name.',
                    },
                    {
                        'name': 'start',
                        'doc': 'beginning index of entry in access list',
                    },
                    {
                        'name': 'increment',
                        'doc': 'increment factor of subsequent ACE in ACL',
                    },
                ],
            },
            {
                'command': 'radius-server host {ip_addr} auth-port {port}',
                'doc': 'Radius server auth-port configuration',
                'arguments': [
                    {
                        'name': 'ip_addr',
                        'doc': 'Radius server IPv4 address',
                    },
                    {
                        'name': 'port',
                        'doc': '<0-65535>  UDP port range is 0 to 65535',
                    },
                ],
            },
            {
                'command': 'no radius-server host {ip_addr} auth-port {port}',
                'doc': 'Radius server auth-port configuration',
                'arguments': [
                    {
                        'name': 'ip_addr',
                        'doc': 'Radius server IPv4 address',
                    },
                    {
                        'name': 'port',
                        'doc': '<0-65535>  UDP port range is 0 to 65535',
                    },
                ],
            },
            {
                'command': 'radius-server host {ip_addr} key {secret}',
                'doc': 'Radius server key configuration',
                'arguments': [
                    {
                        'name': 'ip_addr',
                        'doc': 'Radius server IPv4 address',
                    },
                    {
                        'name': 'secret',
                        'doc': 'WORD Radius shared secret',
                    },
                ],
            },
            {
                'command': 'no radius-server host {ip_addr} key {secret}',
                'doc': 'Radius server key configuration',
                'arguments': [
                    {
                        'name': 'ip_addr',
                        'doc': 'Radius server IPv4 address',
                    },
                    {
                        'name': 'secret',
                        'doc': 'WORD Radius shared secret',
                    },
                ],
            },
            {
                'command': 'radius-server host {ip_addr}',
                'doc': 'Radius server configuration',
                'arguments': [
                    {
                        'name': 'ip_addr',
                        'doc': 'Radius server IPv4 address',
                    },
                ],
            },
            {
                'command': 'no radius-server host {ip_addr}',
                'doc': 'Radius server configuration',
                'arguments': [
                    {
                        'name': 'ip_addr',
                        'doc': 'Radius server IPv4 address',
                    },
                ],
            },
            {
                'command': 'aaa authentication login {type}',
                'doc': 'AAA authentication login configuration',
                'arguments': [
                    {
                        'name': 'type',
                        'doc': (
                            'local Local authentication'
                            'radius Radius authentication'
                        ),
                    },
                ],
            },
            {
                'command': 'aaa authentication login fallback error local',
                'doc': 'AAA authentication login fallback configuration',
                'arguments': [],
            }
        ]
    }),
    ('route_map', {
        'doc': 'Route-map configuration',
        'arguments': [
            {
                'name': 'routemap_name',
                'doc': 'WORD  Route map tag',
            },
            {
                'name': 'permission',
                'doc': (
                    'deny  Route map denies set operations'
                    'permit  Route map permits set operations'
                ),
            },
            {
                'name': 'seq',
                'doc': (
                    'xr<1-65535>  Sequence to insert to/delete from existing '
                    'route-map entry'
                ),
            },
        ],
        'pre_commands': [
            'config terminal',
            'route-map {routemap_name} {permission} {seq}'
        ],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'description {description}',
                'doc': 'Set description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'LINE  Comment describing this route-map rule',
                    },
                ],
            },
            {
                'command': 'no description {description}',
                'doc': 'Unset description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'LINE  Comment describing this route-map rule',
                    },
                ],
            },
            {
                'command': 'match ip address prefix-list {prefix_name}',
                'doc': 'Set prefix-list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  IP prefix-list name',
                    },
                ],
            },
            {
                'command': 'no match ip address prefix-list',
                'doc': 'Unset prefix-list',
                'arguments': [
                    {
                        'name': 'prefix_name',
                        'doc': 'WORD  IP prefix-list name',
                        'optional': True,
                    },
                ],
            },
            {
                'command': 'set metric {metric}',
                'doc': 'Set metric',
                'arguments': [
                    {
                        'name': 'metric',
                        'doc': '<0-4294967295>  Metric value',
                    },
                ],
            },
            {
                'command': 'no set metric',
                'doc': 'Unset metric',
                'arguments': [
                    {
                        'name': 'metric',
                        'doc': '<0-4294967295>  Metric value',
                        'optional': True,
                    },
                ],
            },
            {
                'command': 'set community {community}',
                'doc': 'Set community',
                'arguments': [
                    {
                        'name': 'community',
                        'doc': (
                            'AA:NN  Community number in aa:nn format or '
                            'local-AS\|no-advertise\|no-export\|internet or '
                            'additive'
                        ),
                    },
                ],
            },
            {
                'command': 'no set community',
                'doc': 'Unset community',
                'arguments': [
                    {
                        'name': 'community',
                        'doc': (
                            'AA:NN  Community number in aa:nn format or'
                            'local-AS\|no-advertise\|no-export\|internet or '
                            'additive'
                        ),
                        'optional': True,
                    },
                ],
            },
        ],
    }),
    ('config_interface', {
        'doc': 'Interface configuration.',
        'arguments': [
            {
                'name': 'portlbl',
                'doc': 'Label that identifies an interface.'
            }
        ],
        'pre_commands': ['config terminal', 'interface {port}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ip address {ipv4} secondary',
                'doc': 'Set secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4} secondary',
                'doc': 'Unset secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6} secondary',
                'doc': 'Set secondary IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6} secondary',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ip ospf authentication message-digest',
                'doc': 'Configure OSPF MD5 authentication',
                'arguments': [],
            },
            {
                'command': 'ip ospf authentication',
                'doc': 'Configure OSPF text authentication',
                'arguments': [],
            },
            {
                'command': 'no ip ospf authentication',
                'doc': 'Remove OSPF text authentication',
                'arguments': [],
            },
            {
                'command': 'ip ospf message-digest-key {key_id}'
                           ' md5 {password_key}',
                'doc': 'Configuring MD5 authentication with encryption',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': '<1-255> key_id range',
                    },
                    {
                        'name': 'password_key',
                        'doc': 'OSPF password key'
                    }
                ],
            },
            {
                'command': 'no ip ospf message-digest-key {key_id}',
                'doc': 'Removing MD5 authentication with encryption',
                'arguments': [
                    {
                        'name': 'key_id',
                        'doc': '<1-255> key_id range',
                    },
                ],
            },
            {
                'command': 'ip ospf authentication-key {auth_key}',
                'doc': 'Configuring text authentication with encryption',
                'arguments': [
                    {
                        'name': 'auth_key',
                        'doc': 'Text authentication Authorization key'
                    }
                ],
            },
            {
                'command': 'no ip ospf authentication-key',
                'doc': 'Removing text authentication with encryption',
                'arguments': [],
            },
            {
                'command': 'routing',
                'doc': 'Configure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'no routing',
                'doc': 'Unconfigure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable an interface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable an interface.',
                'arguments': [],
            },
            {
                'command': 'vlan access {vlan_id}',
                'doc': 'Access configuration',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan access {vlan_id}',
                'doc': 'Remove vlan access',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk allowed {vlan_id}',
                'doc': 'Allow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk allowed {vlan_id}',
                'doc': 'Disallow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk native tag',
                'doc': 'Tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'no vlan trunk native tag',
                'doc': 'Remove tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'vlan trunk native {vlan_id}',
                'doc': 'Native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk native {vlan_id}',
                'doc': 'Remove native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'lacp port-id {port_id}',
                'doc': 'Set port ID used in LACP negotiation.',
                'arguments': [
                    {
                        'name': 'port_id',
                        'doc': '<1-65535>  .The range is 1 to 65535'
                    }
                ],
            },
            {
                'command': 'ip ospf dead-interval {dead_timer}',
                'doc': 'Configure ospf dead_timer',
                'arguments': [
                    {
                        'name': 'dead_timer',
                        'doc': '<1-65535>  dead_timer range',
                    },
                ],
            },
            {
                'command': 'ip ospf hello-interval {hello_timer}',
                'doc': 'Configure ospf hello_timer',
                'arguments': [
                    {
                        'name': 'hello_timer',
                        'doc': '<10-30>  hello interval range',
                    },
                ],
            },
            {
                'command': 'ip ospf priority {ospf_priority}',
                'doc': 'Configure ospf priority',
                'arguments': [
                    {
                        'name': 'ospf_priority',
                        'doc': '<0-255>  . The range is 0 to 255',
                    },
                ],
            },
            {
                'command': 'lacp port-priority {port_priority}',
                'doc': 'Set port priority is used in LACP negotiation.',
                'arguments': [
                    {
                        'name': 'port_priority',
                        'doc': '<1-65535>  The range is 1 to 65535'
                    }
                ],
            },
            {
                'command': 'lag {lag_id}',
                'doc': 'Add the current interface to link aggregation.',
                'arguments': [
                    {
                        'name': 'lag_id',
                        'doc': '<1-2000>  LAG number ranges from 1 to 2000'
                    }
                ],
            },
            {
                'command': 'no lag {lag_id}',
                'doc': 'Remove the current interface to link aggregation.',
                'arguments': [
                    {
                        'name': 'lag_id',
                        'doc': '<1-2000>  LAG number ranges from 1 to 2000'
                    }
                ],
            },
            {
                'command': 'lldp transmit',
                'doc': 'Set the transmission on lldp.',
                'arguments': [],
            },
            {
                'command': 'no lldp transmit',
                'doc': 'Un-set the transmission on lldp.',
                'arguments': [],
            },
            {
                'command': 'lldp receive',
                'doc': 'Set the reception on lldp.',
                'arguments': [],
            },
            {
                'command': 'no lldp receive',
                'doc': 'Un-set the reception on lldp.',
                'arguments': [],
            },
            {
                'command': 'udld enable',
                'doc': 'Enable UDLD in the interface.',
                'arguments': [],
            },
            {
                'command': 'no udld enable',
                'doc': 'Disable UDLD in the interface.',
                'arguments': [],
            },
            {
                'command': 'udld interval {interval}',
                'doc': 'Set the packet interval',
                'arguments': [
                    {
                        'name': 'interval',
                        'doc': '<100-10000> Allowed is 100 ms to 10,000 ms'
                    }
                ],
            },
            {
                'command': 'udld retries {retries}',
                'doc': 'Set the retries',
                'arguments': [
                    {
                        'name': 'retries',
                        'doc': '<3-10> Allowed is from 3 to 10 retries.'
                    }
                ],
            },
            {
                'command': 'udld mode {mode}',
                'doc': 'Set the operation mode',
                'arguments': [
                    {
                        'name': 'mode',
                        'doc': '<forward_then_verify | verify_then_forward>'
                    }
                ],
            },
            {
                'command': 'sflow enable',
                'doc': 'Enable sflow feature on interface',
                'arguments': [],
            },
            {
                'command': 'no sflow enable',
                'doc': 'Disable sflow feature on interface',
                'arguments': [],
            },
            {
                'command': 'split',
                'doc': 'Split parent interface',
                'arguments': [],
            },
            {
                'command': 'no split',
                'doc': 'Disable split parent interface',
                'arguments': [],
            },
            {
                'command': 'autonegotiation on',
                'doc': 'Autonegotiation ON',
                'arguments': [],
            },
            {
                'command': 'autonegotiation off',
                'doc': 'Autonegotiation OFF',
                'arguments': [],
            },
            {
                'command': 'no autonegotiation',
                'doc': 'Disable autonegotiation',
                'arguments': [],
            },
            {
                'command': 'apply qos schedule-profile \
{schedule_profile_name}',
                'doc': 'Apply qos profiles on an interface.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': 'The schedule profile to apply.'
                    }
                ],
            },
            {
                'command': 'no apply qos schedule-profile',
                'doc': 'Clears qos profiles from an interface.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': 'The schedule profile to clear.',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'qos dscp {dscp_map_index}',
                'doc': 'Set the dscp override for the port.',
                'arguments': [
                    {
                        'name': 'dscp_map_index',
                        'doc': 'The index into the dscp map.'
                    }
                ],
            },
            {
                'command': 'no qos dscp',
                'doc': 'Remove the dscp override for the port.',
                'arguments': [],
            },
            {
                'command': 'qos trust {value}',
                'doc': 'Set the qos trust mode for the port.',
                'arguments': [
                    {
                        'name': 'value',
                        'doc': 'The qos trust mode to set.'
                    }
                ],
            },
            {
                'command': 'no qos trust',
                'doc': 'Remove the qos trust mode for the port.',
                'arguments': [],
            },
            {
                'command': 'apply access-list ip {acl_name} in',
                'doc': 'Apply ACL on interface',
                'arguments': [
                    {
                        'name': 'acl_name',
                        'doc': 'Access-list name'
                    }
                ],
            },
            {
                'command': 'no apply access-list ip {acl_name} in',
                'doc': 'Apply no ACL on interface',
                'arguments': [
                    {
                        'name': 'acl_name',
                        'doc': 'Access-list name'
                    }
                ],
            }
        ]
    }),
    ('config_subinterface', {
        'doc': 'Sub-Interface configuration.',
        'arguments': [
            {
                'name': 'portlbl',
                'doc': 'Label that identifies a physical interface.'
            },
            {
                'name': 'subint',
                'doc': 'Label that identifies a subinterface.'
            }
        ],
        'pre_commands': ['config terminal', 'interface {port}.{subint}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Subinterface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Subinterface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Subinterface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Subinterface IPv6 address',
                    },
                ],
            },
            {
                'command': 'encapsulation dot1Q {vlan_id}',
                'doc': 'Set encapsulation type for a subinterface',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier.',
                    },
                ],
            },
            {
                'command': 'no encapsulation dot1Q {vlan_id}',
                'doc': 'Unset encapsulation type for a subinterface',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier.',
                    },
                ],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable a subinterface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable a subinterface.',
                'arguments': [],
            },
        ]
    }),
    ('config_interface_vlan', {
        'doc': 'VLAN configuration.',
        'arguments': [
            {
                'name': 'vlan_id',
                'doc': 'Vlan id within <1-4094> and should not'
                       'be an internal vlan.'
            }
        ],
        'pre_commands': ['config terminal', 'interface vlan {vlan_id}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ip address {ipv4} secondary',
                'doc': 'Set secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4} secondary',
                'doc': 'Unset secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6} secondary',
                'doc': 'Set secondary IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6} secondary',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable an interface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable an interface.',
                'arguments': [],
            },
        ]
    }),
    ('config_interface_loopback', {
        'doc': 'Loopback interface configuration.',
        'arguments': [
            {
                'name': 'loopback_id',
                'doc': 'Loopback  id within  range <1-2147483647> '
            }
        ],
        'pre_commands':
     ['config terminal', 'interface loopback {loopback_id}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IPv4 address for loopback',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Loopback IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IPv4 address for loopback',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Loopback IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address on Loopback',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Loopback IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address on loopback interface',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Loopback IPv6 address',
                    },
                ],
            },
        ]
     }),

    ('config_interface_lag', {
        'doc': 'Configure link-aggregation parameters.',
        'arguments': [
            {
                'name': 'lag',
                'doc': 'LAG number ranges from 1 to 2000.'
            }
        ],
        'pre_commands': ['config terminal', 'interface lag {lag}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip address {ipv4}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ip address {ipv4} secondary',
                'doc': 'Set secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'no ip address {ipv4} secondary',
                'doc': 'Unset secondary IP address',
                'arguments': [
                    {
                        'name': 'ipv4',
                        'doc': 'A.B.C.D/M Interface IP address.',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6}',
                'doc': 'Set IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6}',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'ipv6 address {ipv6} secondary',
                'doc': 'Set secondary IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'no ipv6 address {ipv6} secondary',
                'doc': 'Unset IPv6 address',
                'arguments': [
                    {
                        'name': 'ipv6',
                        'doc': 'X:X::X:X/M  Interface IPv6 address',
                    },
                ],
            },
            {
                'command': 'shutdown',
                'doc': 'Enable an interface.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable an interface.',
                'arguments': [],
            },
            {
                'command': 'routing',
                'doc': 'Configure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'no routing',
                'doc': 'Unconfigure interface as L3.',
                'arguments': [],
            },
            {
                'command': 'vlan access {vlan_id}',
                'doc': 'Access configuration',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan access {vlan_id}',
                'doc': 'Remove vlan access',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk allowed {vlan_id}',
                'doc': 'Allow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk allowed {vlan_id}',
                'doc': 'Disallow VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'vlan trunk native tag',
                'doc': 'Tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'no vlan trunk native tag',
                'doc': 'Remove tag configuration on the trunk port',
                'arguments': [],
            },
            {
                'command': 'vlan trunk native {vlan_id}',
                'doc': 'Native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'no vlan trunk native {vlan_id}',
                'doc': 'Remove native VLAN on the trunk port',
                'arguments': [
                    {
                        'name': 'vlan_id',
                        'doc': '<1-4094>  VLAN identifier'
                    }
                ],
            },
            {
                'command': 'lacp mode passive',
                'doc': 'Sets an interface as LACP passive.',
                'arguments': [],
            },
            {
                'command': 'no lacp mode passive',
                'doc': 'Sets an LACP passive interface off.',
                'arguments': [],
            },
            {
                'command': 'lacp mode active',
                'doc': 'Sets an interface as LACP active.',
                'arguments': [],
            },
            {
                'command': 'no lacp mode active',
                'doc': 'Sets an LACP active interface off.',
                'arguments': [],
            },
            {
                'command': 'lacp fallback',
                'doc': 'Enable LACP fallback mode.',
                'arguments': [],
            },
            {
                'command': 'lacp fallback mode priority',
                'doc': 'Set fallback mode to priority.',
                'arguments': [],
            },
            {
                'command': 'lacp fallback mode all_active',
                'doc': 'Set fallback mode to all_active.',
                'arguments': [],
            },
            {
                'command': 'no lacp fallback mode all_active',
                'doc': 'Set fallback mode to priority.',
                'arguments': [],
            },
            {
                'command': 'lacp fallback timeout {timeout}',
                'doc': 'Set LACP fallback timeout.',
                'arguments': [
                    {
                        'name': 'timeout',
                        'doc': '<1-900>  LACP fallback timeout'
                    }
                ],
            },
            {
                'command': 'no lacp fallback timeout {timeout}',
                'doc': 'Set LACP fallback timeout to zero.',
                'arguments': [
                    {
                        'name': 'timeout',
                        'doc': '<1-900>  LACP fallback timeout'
                    }
                ],
            },
            {
                'command': 'hash l2-src-dst',
                'doc': 'Base the hash on l2-src-dst.',
                'arguments': [],
            },
            {
                'command': 'hash l3-src-dst',
                'doc': 'Base the hash on l3-src-dst.',
                'arguments': [],
            },
            {
                'command': 'hash l4-src-dst',
                'doc': 'Base the hash on l4-src-dst.',
                'arguments': [],
            },
            {
                'command': 'lacp rate fast',
                'doc': 'Set LACP heartbeats are requested at the rate '
                       'of one per second.',
                'arguments': [],
            },
            {
                'command': 'no lacp rate fast',
                'doc': 'Set LACP heartbeats slow which is once every '
                       ' 30 seconds.',
                'arguments': [],
            },
            {
                'command': 'apply qos schedule-profile \
{schedule_profile_name}',
                'doc': 'Apply qos profiles on an interface.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': 'The schedule profile to apply.'
                    }
                ],
            },
            {
                'command': 'no apply qos schedule-profile',
                'doc': 'Clears qos profiles from an interface.',
                'arguments': [
                    {
                        'name': 'schedule_profile_name',
                        'doc': 'The schedule profile to clear.',
                        'optional': True
                    }
                ],
            },
            {
                'command': 'qos dscp {dscp_map_index}',
                'doc': 'Set the dscp override for the port.',
                'arguments': [
                    {
                        'name': 'dscp_map_index',
                        'doc': 'The index into the dscp map.'
                    }
                ],
            },
            {
                'command': 'no qos dscp',
                'doc': 'Remove the dscp override for the port.',
                'arguments': [],
            },
            {
                'command': 'qos trust {value}',
                'doc': 'Set the qos trust mode for the port.',
                'arguments': [
                    {
                        'name': 'value',
                        'doc': 'The qos trust mode to set.'
                    }
                ],
            },
            {
                'command': 'no qos trust',
                'doc': 'Remove the qos trust mode for the port.',
                'arguments': [],
            },
        ]
    }),
    ('config_interface_mgmt', {
        'doc': 'Configure management interface.',
        'arguments': [],
        'pre_commands': ['config terminal', 'interface mgmt'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'ip static {ip}',
                'doc': 'Set IP address',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'Interface IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'no ip static {ip}',
                'doc': 'Unset IP address',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': 'Interface IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'default-gateway {gateway}',
                'doc': 'Configure the Default gateway address (IPv4 and IPv6)',
                'arguments': [
                    {
                        'name': 'gateway',
                        'doc': 'IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'no default-gateway {gateway}',
                'doc': 'Remove the Default gateway address (IPv4 and IPv6)',
                'arguments': [
                    {
                        'name': 'gateway',
                        'doc': 'IP (ipv4 or ipv6) address.',
                    },
                ],
            },
            {
                'command': 'nameserver {primary_nameserver}',
                'doc': 'Configure the nameserver',
                'arguments': [
                    {
                        'name': 'primary_nameserver',
                        'doc': 'Primary nameserver (ipv4 or ipv6) address.',
                    },
                    {
                        'name': 'secondary_nameserver',
                        'doc': 'Secondary nameserver (ipv4 or ipv6) address.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no nameserver {primary_nameserver}',
                'doc': 'Configure the nameserver',
                'arguments': [
                    {
                        'name': 'primary_nameserver',
                        'doc': 'Primary nameserver (ipv4 or ipv6) address.',
                    },
                    {
                        'name': 'secondary_nameserver',
                        'doc': 'Secondary nameserver (ipv4 or ipv6) address.',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'ip dhcp',
                'doc': 'Set the mode as dhcp.',
                'arguments': [],
            },
        ]
    }),
    ('config_router_ospf', {
        'doc': 'OSPF configuration.',
        'arguments': [],
        'pre_commands': ['config terminal', 'router ospf'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'router-id {id}',
                'doc': 'Specifies the OSPF router-ID for a OSPF Router',
                'arguments': [
                    {
                        'name': 'id',
                        'doc': '<A.B.C.D> IPv4 address',
                    },
                ],
            },
            {
                'command': 'no router-id',
                'doc': 'unconfigure router-ID for a OSPF Router',
                'arguments': [],
            },
            {
                'command': 'redistribute static',
                'doc': 'Redistributes the static routes in router',
                'arguments': [],
            },
            {
                'command': 'no redistribute static',
                'doc': 'Removes redistributed the static routes in router',
                'arguments': [],
            },
            {
                'command': 'redistribute connected',
                'doc': 'Redistributes the connected routes in router',
                'arguments': [],
            },
            {
                'command': 'no redistribute connected',
                'doc': 'Removes redistributed the connected routes in router',
                'arguments': [],
            },
            {
                'command': 'redistribute bgp',
                'doc': 'Redistributes the routes learned from BGP',
                'arguments': [],
            },
            {
                'command': 'no redistribute bgp',
                'doc': 'Removes redistributed the routes learned from BGP',
                'arguments': [],
            },
            {
                'command': 'default-information originate always',
                'doc': 'Redistributes default routes in router',
                'arguments': [],
            },
            {
                'command': 'no default-information originate always',
                'doc': 'Remove redistributed default routes in router',
                'arguments': [],
            },
            {
                'command': 'area {area_id} authentication message-digest',
                'doc': 'Configures MD5 authentication over area',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'area {area_id} authentication',
                'doc': 'Configures text authentication over area',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'no area {area_id} authentication',
                'doc': 'Removes authentication over area',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'max-metric router-lsa',
                'doc': 'Configures the router as stub router',
                'arguments': [],
            },
            {
                'command': 'max-metric router-lsa on-startup {time}',
                'doc': 'Configures the router as stub router on startup',
                'arguments': [
                    {
                        'name': 'time',
                        'doc': '<5-86400> seconds',
                    },
                ],
            },
            {
                'command': 'area {area_id} nssa',
                'doc': 'Configures area as NSSA',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'area {area_id} nssa no-summary',
                'doc': 'Configures area as NSSA (Totally stubby)',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'area {area_id} stub',
                'doc': 'Configures area as stubby',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'area {area_id} stub no-summary',
                'doc': 'Configures area as Totally stubby',
                'arguments': [
                    {
                        'name': 'area_id',
                        'doc': '<0-4294967295> area range',
                    },
                ],
            },
            {
                'command': 'distance ospf external {external_distance}',
                'doc': 'Configures distance for external routes',
                'arguments': [
                    {
                        'name': 'external_distance',
                        'doc': '<1-255> Distance for external routes',
                    },
                ],
            },
            {
                'command': 'no distance ospf external',
                'doc': 'Removing the distance for external routes',
                'arguments': [],
            },
            {
                'command': 'network {network} area {area}',
                'doc': 'Adds the announcement network for OSPF',
                'arguments': [
                    {
                        'name': 'network',
                        'doc': '<A.B.C.D/M> IPv4 address with the prefix len',
                    },
                    {
                        'name': 'area',
                        'doc': '<0-4228250625 | A.B.C.D> Area-id range'
                    }
                ],
            },
            {
                'command': 'no network {network} area {area}',
                'doc': 'Removes the announcement network for OSPF',
                'arguments': [
                    {
                        'name': 'network',
                        'doc': '<A.B.C.D/M> IPv4 address'
                                ' with the prefix length',
                    },
                    {
                        'name': 'area',
                        'doc': '<0-4228250625 | A.B.C.D> Area-id range'
                    }
                ],
            },
        ]
    }),
    ('config_router_bgp', {
        'doc': 'BGP configuration.',
        'arguments': [
            {
                'name': 'asn',
                'doc': '<1-4294967295> AS number ranges from 1 to 4294967295'
            }
        ],
        'pre_commands': ['config terminal', 'router bgp {asn}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'bgp router-id {id}',
                'doc': 'Specifies the BGP router-ID for a BGP Router',
                'arguments': [
                    {
                        'name': 'id',
                        'doc': '<A.B.C.D> IPv4 address',
                    },
                ],
            },
            {
                'command': 'no bgp router-id {id}',
                'doc': 'Removes the BGP router-ID for a BGP Router',
                'arguments': [
                    {
                        'name': 'id',
                        'doc': '<A.B.C.D> IPv4 address',
                    },
                ],
            },
            {
                'command': 'bgp fast-external-failover',
                'doc': 'Immediately reset session if a link to '
                       'a directly connected external peer goes down',
                'arguments': [],
            },
            {
                'command': 'no bgp fast-external-failover',
                'doc': 'Disables BGP fast external failover',
                'arguments': [],
            },
            {
                'command': 'network {network}',
                'doc': 'Adds the announcement network for BGP',
                'arguments': [
                    {
                        'name': 'network',
                        'doc': '<A.B.C.D/M> IPv4 address with the prefix len',
                    },
                ],
            },
            {
                'command': 'no network {network}',
                'doc': 'Removes the announcement network for BGP',
                'arguments': [
                    {
                        'name': 'network',
                        'doc': '<A.B.C.D/M> IPv4 address'
                                ' with the prefix length',
                    },
                ],
            },
            {
                'command': 'maximum-paths {num}',
                'doc': 'Sets the maximum number of paths for a BGP route',
                'arguments': [
                    {
                        'name': 'num',
                        'doc': '<1-255> Maximum number of paths. Default is 1',
                    },
                ],
            },
            {
                'command': 'no maximum-paths {num}',
                'doc': 'Set the max number of paths to the default value of 1',
                'arguments': [
                    {
                        'name': 'num',
                        'doc': '<1-255> Maximum number of paths. Default is 1',
                    },
                ],
            },
            {
                'command': 'timers bgp {keepalive} {hold}',
                'doc': 'Sets the keepalive interval and hold time '
                       'for a BGP router',
                'arguments': [
                    {
                        'name': 'keepalive',
                        'doc': '<0-65535> Keepalive interval in seconds. '
                               'Default is 60',
                    },
                    {
                        'name': 'hold',
                        'doc': '<0 - 65535> Hold time in seconds. '
                               'Default is 180',
                    },
                ],
            },
            {
                'command': 'no timers bgp',
                'doc': 'Sets the default values for keepalive interval and '
                       'hold time for a BGP router',
                'arguments': [
                    {
                        'name': 'keepalive',
                        'doc': '<0 - 65535> Keepalive interval in seconds. '
                               'Default is 60',
                        'optional': True
                    },
                    {
                        'name': 'hold',
                        'doc': '<0 - 65535> Hold time in seconds. '
                               'Default is 180',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} remote-as {asn}',
                'doc': 'Configures a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'asn',
                        'doc': '<1 - 4294967295> Neighbor AS number. '
                               'Ranges from 1 to 4294967295',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip}',
                'doc': 'Removes a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} route-map {route_name} {action}',
                'doc': 'Configures a BGP neighbor route-map',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'route_name',
                        'doc': 'WORD  Name of route map',
                    },
                    {
                        'name': 'action',
                        'doc': (
                            'export  Apply map to routes coming\n'
                            'from a Route-Server client\n'
                            'import  Apply map to routes going into\n'
                            'a Route-Server client\'s table\n'
                            'in      Apply map to incoming routes\n'
                            'out     Apply map to outbound routes\n'
                        ),
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} route-map {route_name} {action}',
                'doc': 'Unconfigures a BGP neighbor route-map',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'route_name',
                        'doc': 'WORD  Name of route map',
                    },
                    {
                        'name': 'action',
                        'doc': (
                            'export  Apply map to routes coming\n'
                            'from a Route-Server client\n'
                            'import  Apply map to routes going into\n'
                            'a Route-Server client\'s table\n'
                            'in      Apply map to incoming routes\n'
                            'out     Apply map to outbound routes\n'
                        ),
                    },
                ],
            },
            {
                'command': 'neighbor {peer} prefix-list {prefix_name}',
                'doc': 'Applies a prefix-list to the neighbor to filter '
                       'updates to and from the neighbor',
                'arguments': [
                    {
                        'name': 'peer',
                        'doc': '<A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address'
                               ' or neighbor tag',
                    },
                    {
                        'name': 'prefix_name',
                        'doc': '<WORD> The name of a prefix list',
                    },
                    {
                        'name': 'filter_direction',
                        'doc': '<in|out> Filters incoming/outgoing routes',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no neighbor {peer} prefix-list {prefix_name}',
                'doc': 'Remove a prefix-list filter from the neighbor',
                'arguments': [
                    {
                        'name': 'peer',
                        'doc': '<A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address'
                               ' or neighbor tag',
                    },
                    {
                        'name': 'prefix_name',
                        'doc': '<WORD> The name of a prefix list',
                    },
                    {
                        'name': 'filter_direction',
                        'doc': '<in|out> Filters incoming/outgoing routes',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} description {text}',
                'doc': 'Removes a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'text',
                        'doc': 'Description of the peer router. '
                               'String of maximum length 80 chars',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} description',
                'doc': 'Removes a BGP neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'text',
                        'doc': (
                            'Description of the peer router.'
                            'String of maximum length 80 chars'
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} password {pwd}',
                'doc': 'Enables MD5 authentication on a TCP connection '
                       'between BGP peers.',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'pwd',
                        'doc': (
                            'Password in plain text.'
                            'String of maximum length 80 chars'
                        ),
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} password',
                'doc': 'Removes MD5 authentication on a TCP connection '
                       'between BGP peers.',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} timers {keepalive} {hold}',
                'doc': 'Sets the keepalive interval and hold time '
                       'for a specific BGP peer',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'keepalive',
                        'doc': (
                            '<0 - 65535> Keepalive interval in seconds.'
                            'Default is 60'
                        ),
                    },
                    {
                        'name': 'hold',
                        'doc': '<0-65535> Hold time in seconds. Default is 180'
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} timers',
                'doc': 'Sets the default values for keepalive interval '
                       'and hold time for a specific BGP peer',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'keepalive',
                        'doc': (
                            '<0 - 65535> Keepalive interval in seconds.'
                            'Default is 0'
                        ),
                        'optional': True
                    },
                    {
                        'name': 'hold',
                        'doc': '<0 - 65535> Hold time in seconds. '
                               'Default is 0',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} allowas-in',
                'doc': 'Specifies an allow-as-in occurrence number '
                       'for an AS to be in the AS path',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'val',
                        'doc': (
                            '<0 - 10> Number of times BGP can allow an '
                            'instance of AS to be in the AS_PATH'
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} allowas-in',
                'doc': 'Clears the allow-as-in occurrence number for '
                       'an AS to be in the AS path',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                    {
                        'name': 'val',
                        'doc': (
                            '<0 - 10> Number of times BGP can allow an'
                            'instance of AS to be in the AS_PATH'
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'neighbor {ip} remove-private-AS',
                'doc': (
                    'Removes private AS numbers from the AS path'
                    'in outbound routing updates'
                ),
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} remove-private-AS',
                'doc': 'Resets to a cleared state (default)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} soft-reconfiguration inbound',
                'doc': 'Enables software-based reconfiguration to generate '
                       'updates from a neighbor without clearing the BGP '
                       'session',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} soft-reconfiguration inbound',
                'doc': 'Resets to a cleared state (default)',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip} shutdown',
                'doc': (
                    'Shuts down the neighbor. This disables the peer router'
                    'but preserves neighbor configuration'
                ),
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'no neighbor {ip} shutdown',
                'doc': 'Re-enables the neighbor',
                'arguments': [
                    {
                        'name': 'ip',
                        'doc': '<A.B.C.D> Neighbor IPv4 address',
                    },
                ],
            },
            {
                'command': 'neighbor {ip_or_group} peer-group',
                'doc': 'Assigns a neighbor to a peer-group',
                'arguments': [
                    {
                        'name': 'ip_or_group',
                        'doc': (
                            '<A.B.C.D> Neighbor IPv4 address'
                            '<X:X::X:X> Neighbor IPv6 address'
                            '<WORD> Neighbor group'
                        ),
                    },
                    {
                        'name': 'group',
                        'doc': (
                            'Peer-group name.'
                            'String of maximum length 80 chars',
                        ),
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no neighbor {ip_or_group} peer-group',
                'doc': 'Removes the neighbor from the peer-group',
                'arguments': [
                    {
                        'name': 'ip_or_group',
                        'doc': (
                            '<A.B.C.D> Neighbor IPv4 address'
                            '<X:X::X:X> Neighbor IPv6 address'
                            '<WORD> Neighbor group'
                        ),
                    },
                    {
                        'name': 'group',
                        'doc': 'Peer-group name. '
                               'String of maximum length 80 chars',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'redistribute {type}',
                'doc': 'Configures route redistribution of the '
                       'specified protocol into BGP',
                'arguments': [
                    {
                        'name': 'type',
                        'doc': (
                            '<connected | static | ospf>'
                        ),
                    },
                ],
            },
            {
                'command': 'no redistribute {type}',
                'doc': 'Unconfigures route redistribution of the '
                       'specified protocol into BGP',
                'arguments': [
                    {
                        'name': 'type',
                        'doc': (
                            '<connected | static | ospf>'
                        ),
                    },
                ],
            },
        ]
    }),
    ('config_vlan', {
        'doc': 'VLAN configuration.',
        'arguments': [
            {
                'name': 'vlan_id',
                'doc': '<1-4094>  VLAN identifier.'
            }
        ],
        'pre_commands': ['config terminal', 'vlan {vlan_id}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'shutdown',
                'doc': 'Enable the VLAN.',
                'arguments': [],
            },
            {
                'command': 'no shutdown',
                'doc': 'Disable the VLAN.',
                'arguments': [],
            },
            {
                'command': 'description {description}',
                'doc': 'Set VLAN description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'VLAN description.',
                    }
                ],
            },
            {
                'command': 'no description {description}',
                'doc': 'Un-set VLAN description',
                'arguments': [
                    {
                        'name': 'description',
                        'doc': 'VLAN description.',
                    }
                ],
            }
        ]
    },
    ),
    ('config_tftp_server', {
        'doc': 'tftp-server configuration.',
        'arguments': [],
        'pre_commands': ['config terminal', 'tftp-server'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'enable',
                'doc': 'Enable tftp server.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'no enable',
                'doc': 'Disable tftp server.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'path {path}',
                'doc': 'Set Path of tftp-server',
                'arguments': [
                    {
                        'name': 'path',
                        'doc': 'path of the directory'
                    }
                ],
                'returns': True
            },
            {
                'command': 'no path {path}',
                'doc': 'Unset path to tftp server.',
                'arguments': [
                    {
                        'name': 'path',
                        'doc': 'path of the directory'
                    }
                ],
                'returns': True
            },
            {
                'command': 'secure-mode',
                'doc': 'Enable secure mode for tftp server.',
                'arguments': [],
                'returns': True
            },
            {
                'command': 'no secure-mode',
                'doc': 'Disable secure mode for tftp server.',
                'arguments': [],
                'returns': True
            },
        ]
    },
    ),
    (
        'config_dhcp_server', {
            'doc': 'DHCP server configuration.',
            'arguments': [],
            'pre_commands': ['config terminal', 'dhcp-server'],
            'post_commands': ['end'],
            'commands': [
                {
                    'command': (
                        'range {range_name} start-ip-address {start_ip}'
                        ' end-ip-address {end_ip}'
                    ),
                    'doc': 'Sets DHCP dynamic configuration.',
                    'arguments': [
                        {
                            'name': 'range_name',
                            'doc': (
                                'DHCP range name. '
                                'String of maximum length 15 chars'
                            ),
                        },
                        {
                            'name': 'start_ip',
                            'doc': (
                                '<A.B.C.D> Start range IPv4 address or '
                                '<X:X::X:X> Start range IPv6 address'
                            ),
                        },
                        {
                            'name': 'end_ip',
                            'doc': (
                                '<A.B.C.D> End range IPv4 address or '
                                '<X:X::X:X> End range IPv6 address'
                            ),
                        },
                        {
                            'name': 'subnet_mask',
                            'doc': '<A.B.C.D> Range netmask address',
                            'prefix': ' netmask ',
                            'optional': True
                        },
                        {
                            'name': 'broadcast_address',
                            'doc': '<A.B.C.D> Range broadcast address',
                            'optional': True,
                            'prefix': ' broadcast '
                        },
                        {
                            'name': 'tag_name',
                            'doc': (
                                'Match tags list. '
                                'Each tag length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match tags '
                        },
                        {
                            'name': 'set_name',
                            'doc': (
                                'Tag set name. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' set tag '
                        },
                        {
                            'name': 'prefix_len_value',
                            'doc': (
                                'IPV6 prefix length. '
                                '<64 - 128> Configurable range.'
                            ),
                            'optional': True,
                            'prefix': ' prefix-len '
                        },
                        {
                            'name': 'lease_duration_value',
                            'doc': (
                                'Range lease duration. '
                                'Default value is 60 min.'
                            ),
                            'optional': True,
                            'prefix': ' lease-duration '
                        },
                    ],
                },
                {
                    'command': (
                        'no range {range_name} '
                        'start-ip-address {start_ip} '
                        'end-ip-address {end_ip} '
                    ),
                    'doc': 'Removes DHCP dynamic configuration.',
                    'arguments': [
                        {
                            'name': 'range_name',
                            'doc': (
                                    'DHCP range name. '
                                    'String of maximum length 15 chars'
                            ),
                        },
                        {
                            'name': 'start_ip',
                            'doc': (
                                '<A.B.C.D> Start range IPv4 address or '
                                '<X:X::X:X> Start range IPv6 address'
                            ),
                        },
                        {
                            'name': 'end_ip',
                            'doc': (
                                '<A.B.C.D> End range IPv4 address or '
                                '<X:X::X:X> End range IPv6 address'
                            ),
                        },
                        {
                            'name': 'subnet_mask',
                            'doc': '<A.B.C.D> Range netmask address',
                            'optional': True,
                            'prefix': ' netmask '
                        },
                        {
                            'name': 'broadcast_address',
                            'doc': '<A.B.C.D> Range broadcast address',
                            'optional': True,
                            'prefix': ' broadcast '
                        },
                        {
                            'name': 'tag_name',
                            'doc': (
                                'Match tags list. '
                                'Each tag length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match tags '
                        },
                        {
                            'name': 'set_name',
                            'doc': (
                                'Tag set name. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' set tag '
                        },
                        {
                            'name': 'prefix_len_value',
                            'doc': (
                                'IPV6 prefix length. '
                                '<64 - 128> Configurable range.'
                            ),
                            'optional': True,
                            'prefix': ' prefix-len '
                        },
                        {
                            'name': 'lease_duration_value',
                            'doc': (
                                'Range lease duration. '
                                'Default value is 60 min.'
                            ),
                            'optional': True,
                            'prefix': ' lease-duration '
                        },
                    ],
                },
                {
                    'command': (
                        'static {ip_address}'
                    ),
                    'doc': 'Sets DHCP dynamic configuration.',
                    'arguments': [
                        {
                            'name': 'ip_address',
                            'doc': (
                                '<A.B.C.D> IPv4 address or '
                                '<X:X::X:X> IPv6 address'
                            ),
                        },
                        {
                            'name': 'mac_address',
                            'doc': (
                                '<XX:XX:XX:XX:XX:XX> MAC address or '
                                '<XX-XX-XX-XX-XX-XX> MAC address'
                                'Client MAC addresses'
                            ),
                            'optional': True,
                            'prefix': ' match-mac-addresses '
                        },
                        {
                            'name': 'hostname',
                            'doc': (
                                'Client hostname. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match-client-hostname '
                        },
                        {
                            'name': 'client_id',
                            'doc': (
                                'Client id. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match-client-id '
                        },
                        {
                            'name': 'set_tag_names',
                            'doc': (
                                'Set tag list names. '
                                'Each tag length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' set tags '
                        },
                        {
                            'name': 'lease_duration_value',
                            'doc': (
                                'Range lease duration. '
                                'Default value is 60 min.'
                            ),
                            'optional': True,
                            'prefix': ' lease-duration '
                        },
                    ],
                },
                {
                    'command': (
                        'no static {ip_address}'
                    ),
                    'doc': 'Removes DHCP dynamic configuration.',
                    'arguments': [
                        {
                            'name': 'ip_address',
                            'doc': (
                                '<A.B.C.D> IPv4 address or '
                                '<X:X::X:X> IPv6 address'
                            ),
                        },
                        {
                            'name': 'mac_address',
                            'doc': (
                                '<XX:XX:XX:XX:XX:XX> MAC address or '
                                '<XX-XX-XX-XX-XX-XX> MAC address'
                                'Client MAC addresses'
                            ),
                            'optional': True,
                            'prefix': ' match-mac-addresses '
                        },
                        {
                            'name': 'hostname',
                            'doc': (
                                'Client hostname '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match-client-hostname '
                        },
                        {
                            'name': 'client_id',
                            'doc': (
                                'Client id. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match-client-id '
                        },
                        {
                            'name': 'set_tag_names',
                            'doc': (
                                'Set tag list names. '
                                'Each tag length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' set tags '
                        },
                        {
                            'name': 'lease_duration_value',
                            'doc': (
                                'Range lease duration. '
                                'Default value is 60 min.'
                            ),
                            'optional': True,
                            'prefix': ' lease-duration '
                        },
                    ],
                },
                {
                    'command': (
                        'option set'
                    ),
                    'doc': (
                        'Sets DHCP configuration values using an option name.'
                    ),
                    'arguments': [
                        {
                            'name': 'option_name',
                            'doc': 'DHCP option name',
                            'prefix': ' option-name ',
                            'optional': True
                        },
                        {
                            'name': 'option_number',
                            'doc': 'DHCP option number',
                            'prefix': ' option-number ',
                            'optional': True
                        },
                        {
                            'name': 'option_value',
                            'doc': 'DHCP option value',
                            'prefix': ' option-value ',
                            'optional': True
                        },
                        {
                            'name': 'tag_name',
                            'doc': (
                                'Match tags list. '
                                'Each tag length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match tags'
                        },
                        {
                            'name': 'ipv6',
                            'doc': (
                                'Enable ipv6 for the set.'
                            ),
                            'optional': True,
                        },
                    ],
                },
                {
                    'command': (
                        'no option set'
                    ),
                    'doc': (
                        'Removes DHCP configuration '
                        'values using an option name.'
                    ),
                    'arguments': [
                        {
                            'name': 'option_name',
                            'doc': 'DHCP option name',
                            'prefix': ' option-name ',
                            'optional': True
                        },
                        {
                            'name': 'option_number',
                            'doc': 'DHCP option number',
                            'prefix': ' option-number ',
                            'optional': True
                        },
                        {
                            'name': 'option_value',
                            'doc': 'DHCP option value',
                            'prefix': ' option-value ',
                            'optional': True
                        },
                        {
                            'name': 'tag_name',
                            'doc': (
                                'Match tags list. '
                                'Each tag length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match-tags ',
                        },
                        {
                            'name': 'ipv6',
                            'doc': (
                                'Enable ipv6 for the set.'
                            ),
                            'optional': True,
                        },
                    ],
                },
                {
                    'command': (
                        'match set tag {tag_name}'
                    ),
                    'doc': (
                        'Sets DHCP match configuration using an option name.'
                    ),
                    'arguments': [
                        {
                            'name': 'tag_name',
                            'doc': (
                                'DHCP match tag name'
                                'Length must be less than 15 chars.'
                            ),
                        },
                        {
                            'name': 'option_number',
                            'doc': (
                                'DHCP option number. '
                                '<0 - 255> Configurable range.'
                            ),
                            'prefix': ' match-option-number ',
                            'optional': True
                        },
                        {
                            'name': 'option_name',
                            'doc': (
                                'DHCP option name. '
                                'Length must be less than 15 chars.'
                            ),
                            'prefix': ' match-option-name ',
                            'optional': True
                        },
                        {
                            'name': 'option_value',
                            'doc': 'DHCP option value',
                            'optional': True,
                            'prefix': ' match-option-value '
                        },
                    ],
                },
                {
                    'command': (
                        'no match set tag {tag_name}'
                    ),
                    'doc': (
                        'Removes DHCP match configuration '
                        'using an option name.'
                    ),
                    'arguments': [
                        {
                            'name': 'tag_name',
                            'doc': (
                                'DHCP match tag name'
                                'Length must be less than 15 chars.'
                            ),
                        },
                        {
                            'name': 'option_name',
                            'doc': (
                                'DHCP option name. '
                                'Length must be less than 15 chars.'
                            ),
                            'prefix': ' match-option-name ',
                            'optional': True
                        },
                        {
                            'name': 'option_number',
                            'doc': (
                                'DHCP option number. '
                                '<0 - 255> Configurable range.'
                            ),
                            'prefix': ' match-option-number ',
                            'optional': True
                        },
                        {
                            'name': 'option_value',
                            'doc': 'DHCP option value',
                            'optional': True,
                            'prefix': ' match-option-value '
                        },
                    ],
                },
                {
                    'command': (
                        'boot set file {file_name}'
                    ),
                    'doc': 'Sets DHCP bootp options.',
                    'arguments': [
                        {
                            'name': 'file_name',
                            'doc': 'DHCP boot file name'
                        },
                        {
                            'name': 'tag_name',
                            'doc': (
                                'DHCP match tag name. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match tag '
                        },
                    ],
                },
                {
                    'command': (
                        'no boot set file {file_name}'
                    ),
                    'doc': 'Removes bootp options.',
                    'arguments': [
                        {
                            'name': 'file_name',
                            'doc': 'DHCP boot file name'
                        },
                        {
                            'name': 'tag_name',
                            'doc': (
                                'DHCP match tag name. '
                                'Length must be less than 15 chars.'
                            ),
                            'optional': True,
                            'prefix': ' match tag '
                        },
                    ],
                }
            ]
        },
    ),
    ('config_mirror_session', {
        'doc': 'Mirror session configuration.',
        'arguments': [
            {
                'name': 'name',
                'doc': (
                    'Up to 64 letters, numbers, underscores, dashes, '
                    'or periods.'
                )
            }
        ],
        'pre_commands': ['config terminal', 'mirror session {name}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'destination interface {portlbl}',
                'doc': 'Set the destination interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies an interface or LAG'
                    }
                ]
            },
            {
                'command': 'no destination interface',
                'doc': (
                    'Un-set the destination interface and '
                    'shutdown the session.'
                ),
                'arguments': []
            },
            {
                'command': 'shutdown',
                'doc': 'Shutdown the mirroring session.',
                'arguments': []
            },
            {
                'command': 'no shutdown',
                'doc': 'Activate the mirroring session.',
                'arguments': []
            },
            {
                'command': 'source interface {portlbl} {direction}',
                'doc': 'Assign a source interface.',
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Label that identifies an interface or LAG'
                    },
                    {
                        'name': 'direction',
                        'doc': (
                            '<both | rx | tx>'
                        ),
                    }
                ]
            },
            {
                'command': 'no source interface {portlbl}',
                'doc': (
                    'Remove a source interface from the session.'
                ),
                'arguments': [
                    {
                        'name': 'portlbl',
                        'doc': 'Ethernet interface or LAG'
                    },
                    {
                        'name': 'direction',
                        'doc': (
                            '<both | rx | tx>'
                        ),
                        'optional': True,
                    }
                ]
            }
        ]
    },
    ),
    ('config_queue_profile', {
        'doc': 'Configure a queue profile.',
        'arguments': [
            {
                'name': 'name',
                'doc': (
                    'Up to 64 letters, numbers, underscores, dashes, '
                    'or periods.'
                )
            }
        ],
        'pre_commands': ['config terminal', 'qos queue-profile {name}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'map queue {queue} local-priority {local_priority}',
                'doc': 'Map a local priority to a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to configure.'
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority to configure.'
                    }
                ]
            },
            {
                'command': 'no map queue {queue}',
                'doc': 'Clear the map for a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to clear.'
                    }
                ]
            },
            {
                'command': 'no map queue {queue} \
local-priority {local_priority}',
                'doc': 'Clear a local priority from a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to configure.'
                    },
                    {
                        'name': 'local_priority',
                        'doc': 'The local priority to configure.'
                    }
                ]
            },
            {
                'command': 'name queue {queue} {name}',
                'doc': 'Name a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to configure.'
                    },
                    {
                        'name': 'name',
                        'doc': 'The name to assign to the queue.'
                    }
                ]
            },
            {
                'command': 'no name queue {queue}',
                'doc': 'Clears the name of a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to clear.'
                    }
                ]
            }
        ]
    },
    ),
    ('config_schedule_profile', {
        'doc': 'Configure a schedule profile.',
        'arguments': [
            {
                'name': 'name',
                'doc': (
                    'Up to 64 letters, numbers, underscores, dashes, '
                    'or periods.'
                )
            }
        ],
        'pre_commands': ['config terminal', 'qos schedule-profile {name}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': 'strict queue {queue}',
                'doc': 'Assign the strict algorithm to a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to configure.'
                    },
                ]
            },
            {
                'command': 'no strict queue {queue}',
                'doc': 'Clear the strict algorithm from a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to clear.'
                    }
                ]
            },
            {
                'command': 'dwrr queue {queue} weight {weight}',
                'doc': 'Assign the dwrr algorithm to a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to configure.'
                    },
                    {
                        'name': 'weight',
                        'doc': 'The weight for the queue.'
                    }
                ]
            },
            {
                'command': 'no dwrr queue {queue}',
                'doc': 'Clears the dwrr algorithm for a queue.',
                'arguments': [
                    {
                        'name': 'queue',
                        'doc': 'The queue to clear.'
                    },
                ]
            }
        ]
    },
    ),
    ('config_access_list_ip_testname', {
        'doc': 'ACE permission.',
        'arguments': [
            {
                'name': 'acl_name',
                'doc': 'access-list name'
            }
        ],
        'pre_commands': ['config terminal', 'access-list ip {acl_name}'],
        'post_commands': ['end'],
        'commands': [
            {
                'command': '{negate} {sequence} permit {protocol} '
                           '{ip1} {port1} {ip2} {port2} {count} {log}',
                'doc': 'Permit access-list entry',
                'arguments': [
                    {
                        'name': 'negate',
                        'doc': 'remove access-list entry.',
                    },
                    {
                        'name': 'sequence',
                        'doc': 'sequence number of ACE.',
                    },
                    {
                        'name': 'protocol',
                        'doc': 'Protocol (number) type.',
                    },
                    {
                        'name': 'ip1',
                        'doc': '<A.B.C.D/M> Source IPv4 address.',
                    },
                    {
                        'name': 'port1',
                        'doc': 'Source Port range <1-65535>.',
                    },
                    {
                        'name': 'ip2',
                        'doc': '<A.B.C.D/M> Destination IPv4 address.',
                    },
                    {
                        'name': 'port2',
                        'doc': 'Destination Port range <1-65535>.',
                    },
                    {
                        'name': 'count',
                        'doc': 'TBD',
                        'optional': True
                    },
                    {
                        'name': 'log',
                        'doc': 'TBD',
                        'optional': True
                    },
                ],
            },
            {
                'command': '{negate} {sequence} deny {protocol} '
                           '{ip1} {port1} {ip2} {port2} {count} {log}',
                'doc': 'Deny access-list entry',
                'arguments': [
                    {
                        'name': 'negate',
                        'doc': 'remove access-list entry.',
                    },
                    {
                        'name': 'sequence',
                        'doc': 'sequence number of ACE.',
                    },
                    {
                        'name': 'protocol',
                        'doc': 'Protocol type for entry.',
                    },
                    {
                        'name': 'ip1',
                        'doc': '<A.B.C.D/M> Source IPv4 address.',
                    },
                    {
                        'name': 'port1',
                        'doc': 'Source Port range <1-65535>.',
                    },
                    {
                        'name': 'ip2',
                        'doc': '<A.B.C.D/M> Destination IPv4 address.',
                    },
                    {
                        'name': 'port2',
                        'doc': 'Destination Port range <1-65535>.',
                    },
                    {
                        'name': 'count',
                        'doc': 'TBD',
                        'optional': True
                    },
                    {
                        'name': 'log',
                        'doc': 'TBD',
                        'optional': True
                    },
                ],
            },
            {
                'command': 'no {sequence}',
                'doc': 'Remove access-list entry',
                'arguments': [
                    {
                        'name': 'sequence',
                        'doc': 'sequence number of ACE.',
                    },
                ],
            },
        ]
    })
])

"""Vtysh Specification as a Python dictionary"""


VTYSH_EXCEPTIONS_SPEC = OrderedDict([
    (
        'UnknownCommandException',
        [
            'unknown command',
        ]
    ), (
        'IncompleteCommandException',
        [
            'command incomplete',
        ]
    ), (
        'NotValidLAG',
        [
            'specified lag port does not exist.',
        ]
    ), (
        'DuplicateLoopbackIPException',
        [
            'ip address is already assigned to interface'
            ' as primary.',
        ]
    ), (
        'InvalidQnCommandException',
        [
            'name  acl name',
        ]
    ), (
        'AclEmptyException',
        [
            'acl is empty',
        ]
    ), (
        'TcamResourcesException',
        [
            'command failed',
        ]
    ), (
        'ResequenceNumberException',
        [
            'sequence numbers would exceed maximum',
        ]
    ), (
        'AmbiguousCommandException',
        [
            'ambiguous command',
        ]
    ), (
        'InvalidL4SourcePortRangeException',
        [
            'invalid l4 source port range',
        ]
    ), (
        'EchoCommandException',
        [
            'range',
        ]
    ), (
        'AceDoesNotExistException',
        [
            'acl entry does not exist',
        ]
    ), (
        'AclDoesNotExistException',
        [
            'acl does not exist',
        ]
    )
])
"""Vtysh Exceptions specification as a Python dictionary"""


__all__ = ['VTYSH_SPEC', 'VTYSH_EXCEPTIONS_SPEC']
