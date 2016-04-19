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
                'command': 'show startup-config',
                'doc': 'Show startup-config information.',
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
                'command': 'show mirror {name}',
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
                'command': 'snmp-server host {host_ip_address} trap version \
                            {snmp_version}',
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
                         'name': 'community-name',
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
                         'name': 'snmp-port',
                         'doc': 'Configured snmp port for trap receiver',
                         'optional': True
                    }
                ],
            },
            {
                'command': 'no snmp-server host {host_ip_address} trap \
                            version {snmp_version}',
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
                         'name': 'community-name',
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
                         'name': 'snmp-port',
                         'doc': 'Unconfigured snmp port for trap receiver',
                         'optional': True
                    }
                ],
            },
            {
                'command': 'snmp-server inform {host_ip_address} trap version \
                            {snmp_version}',
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
                         'name': 'community-name',
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
                         'name': 'snmp-port',
                         'doc': 'Configured snmp port for notifications',
                         'optional': True
                    }
                ],
            },
            {
                'command': 'no snmp-server inform {host_ip_address} trap\
                            version {snmp_version}',
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
                         'name': 'community-name',
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
                         'name': 'snmp-port',
                         'doc': 'Unconfigured snmp port for notifications',
                         'optional': True
                    }
                ],
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
                        'doc': '<1-65535>  hello_timer range',
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
                'command': 'lldp transmission',
                'doc': 'Set the transmission on lldp.',
                'arguments': [],
            },
            {
                'command': 'no lldp transmission',
                'doc': 'Un-set the transmission on lldp.',
                'arguments': [],
            },
            {
                'command': 'lldp reception',
                'doc': 'Set the reception on lldp.',
                'arguments': [],
            },
            {
                'command': 'no lldp reception',
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
                'command': 'no router-id {id}',
                'doc': 'Specifies the OSPF router-ID for a OSPF Router',
                'arguments': [
                    {
                        'name': 'id',
                        'doc': '<A.B.C.D> IPv4 address',
                    },
                ],
            },
            {
                'command': 'max-metric router-lsa',
                'doc': 'Configures the router as stub router',
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
            }
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
                            'name': 'set_name',
                            'doc': 'DHCP option name',
                            'prefix': ' option-name ',
                            'optional': True
                        },
                        {
                            'name': 'option-number',
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
                            'name': 'set_name',
                            'doc': 'DHCP option name',
                            'prefix': ' option-name ',
                            'optional': True
                        },
                        {
                            'name': 'option-number',
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
                'command': 'destination interface',
                'doc': 'Set the destination interface.',
                'arguments': [
                    {
                        'name': 'interface',
                        'doc': 'Ethernet interface or LAG'
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
                'command': 'source interface',
                'doc': 'Assign a source interface.',
                'arguments': [
                    {
                        'name': 'interface',
                        'doc': 'Ethernet interface or LAG'
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
                'command': 'no source interface',
                'doc': (
                    'Remove a source interface from the session.'
                ),
                'arguments': [
                    {
                        'name': 'interface',
                        'doc': 'Ethernet interface or LAG'
                    }
                ]
            }
        ]
    },
    )
])

"""Vtysh Specification as a Python dictionary"""


VTYSH_EXCEPTIONS_SPEC = OrderedDict([
    (
        'UnknownCommandException',
        [
            'Unknown command', '% Unknown command.'
        ]
    ), (
        'IncompleteCommandException',
        [
            'Command incomplete',
        ]
    ), (
        'NotValidLAG',
        [
            'Specified LAG port does not exist.',
        ]
    ), (
        'DuplicateLoopbackIPException',
        [
            'IP address is already assigned to interface. [A-Za-z0-9]+\
             as primary.',
        ]
    )
])
"""Vtysh Exceptions specification as a Python dictionary"""


__all__ = ['VTYSH_SPEC', 'VTYSH_EXCEPTIONS_SPEC']
