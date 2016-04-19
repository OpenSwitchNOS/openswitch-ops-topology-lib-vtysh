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
Vtysh auto-generated communication library module.

.. warning::

   This is auto-generated, do not modify manually!!
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from .parser import *  # noqa
from .exceptions import determine_exception


class ContextManager(object):
    """
    This class defines a context manager object.

    Usage:

    ::

        with ClassName(parameters) as ctx:
            ctx.first_function()
            ctx.second_function()

    This way at the beginning the **pre_commands** will be run and at the end
    the **post_commands** will clean the vtysh terminal. Every implementation
    of this class document their pre_commands and post_commands.

    """


class Configure(ContextManager):
    """
    Configuration terminal

    pre_commands:

    ::

            ['configure terminal']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            configure terminal
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def no_vlan(
            self, vlan_id):
        """
        Delete a VLAN

        This function runs the following vtysh command:

        ::

            # no vlan {vlan_id}

        :param vlan_id: VLAN Identifier.
        """

        cmd = [
            'no vlan {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_interface_lag(
            self, lag_id):
        """
        Delete a lag

        This function runs the following vtysh command:

        ::

            # no interface lag {lag_id}

        :param lag_id: link-aggregation identifier.
        """

        cmd = [
            'no interface lag {lag_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_interface_loopback(
            self, loopback_id):
        """
        Delete a L3 loopback interface

        This function runs the following vtysh command:

        ::

            # no interface loopback {loopback_id}

        :param loopback_id: Loopback interface identifier.
        """

        cmd = [
            'no interface loopback {loopback_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_route(
            self, ipv4, next_hop, metric=''):
        """
        Configure static routes

        This function runs the following vtysh command:

        ::

            # ip route {ipv4} {next_hop}

        :param ipv4: A.B.C.D/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = [
            'ip route {ipv4} {next_hop}'
        ]

        if metric:
            cmd.append(
                '{}{{metric}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_route(
            self, ipv4, next_hop, metric=''):
        """
        Un-configure static routes

        This function runs the following vtysh command:

        ::

            # no ip route {ipv4} {next_hop}

        :param ipv4: A.B.C.D/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = [
            'no ip route {ipv4} {next_hop}'
        ]

        if metric:
            cmd.append(
                '{}{{metric}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Configure prefix list

        This function runs the following vtysh command:

        ::

            # ip prefix-list {prefix_name} seq {seq} {permission} {network}

        :param prefix_name: WORD  Name of a prefix list.
        :param seq: <1-4294967295>  Sequence number.
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: A.B.C.D/M  IP prefix <network>/<length>, e.g.,
            35.0.0.0/8 any Any prefix match. Same as "0.0.0.0/0 le 32"
        """

        cmd = [
            'ip prefix-list {prefix_name} seq {seq} {permission} {network}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Un-configure prefix list

        This function runs the following vtysh command:

        ::

            # no ip prefix-list {prefix_name} seq {seq} {permission} {network}

        :param prefix_name: WORD  Name of a prefix list.
        :param seq: <1-4294967295>  Sequence number.
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: A.B.C.D/M  IP prefix <network>/<length>, e.g.,
            35.0.0.0/8 any Any prefix match. Same as "0.0.0.0/0 le 32"
        """

        cmd = [
            'no ip prefix-list {prefix_name} seq {seq} {permission} {network}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Configure IPv6 prefix-based filtering

        This function runs the following vtysh command:

        ::

            # ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}

        :param prefix_name: WORD  The IP prefix-list name
        :param seq: <1-4294967295>  Sequence number
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: X:X::X:X/M IPv6 prefix
        """

        cmd = [
            'ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_prefix_list_seq(
            self, prefix_name, seq, permission, network):
        """
        Deletes the IPv6 prefix-list

        This function runs the following vtysh command:

        ::

            # no ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}  # noqa

        :param prefix_name: WORD  The IP prefix-list name
        :param seq: <1-4294967295>  Sequence number
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: X:X::X:X/M IPv6 prefix
        """

        cmd = [
            'no ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}'  # noqa
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_route_map(
            self, routemap_name, permission, seq):
        """
        Route-map configuration

        This function runs the following vtysh command:

        ::

            # no route-map {routemap_name} {permission} {seq}

        :param routemap_name: WORD  Route map tag
        :param permission: deny  Route map denies set operationspermit  Route
            map permits set operations
        :param seq: <1-65535>  Sequence to insert to/delete from existing
            route-map entry
        """

        cmd = [
            'no route-map {routemap_name} {permission} {seq}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_route(
            self, ipv6, next_hop, metric=''):
        """
        Configure static routes

        This function runs the following vtysh command:

        ::

            # ipv6 route {ipv6} {next_hop}

        :param ipv6: X:X::X:X/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = [
            'ipv6 route {ipv6} {next_hop}'
        ]

        if metric:
            cmd.append(
                '{}{{metric}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_route(
            self, ipv6, next_hop, metric=''):
        """
        Un-configure static routes

        This function runs the following vtysh command:

        ::

            # no ipv6 route {ipv6} {next_hop}

        :param ipv6: X:X::X:X/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        """

        cmd = [
            'no ipv6 route {ipv6} {next_hop}'
        ]

        if metric:
            cmd.append(
                '{}{{metric}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_system_priority(
            self, priority):
        """
        Set LACP system priority.

        This function runs the following vtysh command:

        ::

            # lacp system-priority {priority}

        :param priority: <0-65535>  The range is 0 to 65535.
        """

        cmd = [
            'lacp system-priority {priority}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_enable(
            self):
        """
        Enable LLDP globally.

        This function runs the following vtysh command:

        ::

            # lldp enable

        """

        cmd = [
            'lldp enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_enable(
            self):
        """
        Disable LLDP globally.

        This function runs the following vtysh command:

        ::

            # no lldp enable

        """

        cmd = [
            'no lldp enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_enable(
            self):
        """
        Configure sFlow.

        This function runs the following vtysh command:

        ::

            # sflow enable

        """

        cmd = [
            'sflow enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_enable(
            self):
        """
        Un-configure sFlow.

        This function runs the following vtysh command:

        ::

            # no sflow enable

        """

        cmd = [
            'no sflow enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_sampling(
            self, rate):
        """
        Set sFlow sampling rate.

        This function runs the following vtysh command:

        ::

            # sflow sampling {rate}

        :param rate: <1-1000000000>  The range is 1 to 1000000000.
        """

        cmd = [
            'sflow sampling {rate}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_sampling(
            self):
        """
        Reset sFlow sampling rate to default.

        This function runs the following vtysh command:

        ::

            # no sflow sampling

        """

        cmd = [
            'no sflow sampling'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_polling(
            self, interval):
        """
        Set sFlow polling interval.

        This function runs the following vtysh command:

        ::

            # sflow polling {interval}

        :param interval: <0-3600>  The range is 0 to 3600.
        """

        cmd = [
            'sflow polling {interval}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_polling(
            self):
        """
        Reset sFlow polling interval to default.

        This function runs the following vtysh command:

        ::

            # no sflow polling

        """

        cmd = [
            'no sflow polling'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_agent_interface(
            self, portlbl, address_family=''):
        """
        Set sFlow agent interface

        This function runs the following vtysh command:

        ::

            # sflow agent-interface {portlbl}

        :param portlbl: Valid L3 interface name.
        :param address_family: Optional, IPv4 or IPv6 (Default : IPv4).
        """

        cmd = [
            'sflow agent-interface {portlbl}'
        ]

        port = self.enode.ports.get(portlbl, portlbl)

        if address_family:
            cmd.append(
                '{}{{address_family}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_agent_interface(
            self):
        """
        Remove sFlow agent interface configuration.

        This function runs the following vtysh command:

        ::

            # no sflow agent-interface

        """

        cmd = [
            'no sflow agent-interface'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector(
            self, ip):
        """
        Set sFlow collector configuration (IP)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip}

        :param ip: IP address of collector.
        """

        cmd = [
            'sflow collector {ip}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_port(
            self, ip, port):
        """
        Set sFlow collector configuration (IP, port)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} port {port}

        :param ip: IP address of collector.
        :param port: Port of collector <0-65535> (Default : 6343).
        """

        cmd = [
            'sflow collector {ip} port {port}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_vrf(
            self, ip, vrf):
        """
        Set sFlow collector configuration (IP, vrf)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} vrf {vrf}

        :param ip: IP address of collector.
        :param vrf: Name of VRF (Default : vrf_default).
        """

        cmd = [
            'sflow collector {ip} vrf {vrf}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_port_vrf(
            self, ip, port, vrf):
        """
        Set sFlow collector configuration (IP, port, vrf)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} port {port} vrf {vrf}

        :param ip: IP address of collector.
        :param port: Port of collector <0-65535> (Default : 6343).
        :param vrf: Name of VRF (Default : vrf_default).
        """

        cmd = [
            'sflow collector {ip} port {port} vrf {vrf}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_router_bgp(
            self, asn):
        """
        Removes the BGP Router

        This function runs the following vtysh command:

        ::

            # no router bgp {asn}

        :param asn: Autonomous System Number.
        """

        cmd = [
            'no router bgp {asn}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_disable(
            self):
        """
        Completely disable ECMP

        This function runs the following vtysh command:

        ::

            # ip ecmp disable

        """

        cmd = [
            'ip ecmp disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_disable(
            self):
        """
        Completely disable ECMP

        This function runs the following vtysh command:

        ::

            # no ip ecmp disable

        """

        cmd = [
            'no ip ecmp disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_dst_ip_disable(
            self):
        """
        Disable load balancing by destination IP

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance dst-ip disable

        """

        cmd = [
            'ip ecmp load-balance dst-ip disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_dst_ip_disable(
            self):
        """
        Disable load balancing by destination IP

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance dst-ip disable

        """

        cmd = [
            'no ip ecmp load-balance dst-ip disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_dst_port_disable(
            self):
        """
        Disable load balancing by destination port

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance dst-port disable

        """

        cmd = [
            'ip ecmp load-balance dst-port disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_dst_port_disable(
            self):
        """
        Disable load balancing by destination port

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance dst-port disable

        """

        cmd = [
            'no ip ecmp load-balance dst-port disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_src_port_disable(
            self):
        """
        Disable load balancing by source port

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance src-port disable

        """

        cmd = [
            'ip ecmp load-balance src-port disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_src_port_disable(
            self):
        """
        Disable load balancing by source port

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance src-port disable

        """

        cmd = [
            'no ip ecmp load-balance src-port disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_src_ip_disable(
            self):
        """
        Disable load balancing by source IP

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance src-ip disable

        """

        cmd = [
            'ip ecmp load-balance src-ip disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_src_ip_disable(
            self):
        """
        Disable load balancing by source IP

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance src-ip disable

        """

        cmd = [
            'no ip ecmp load-balance src-ip disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_resilient_disable(
            self):
        """
        Disable resilient hashing for load balancing

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance resilient disable

        """

        cmd = [
            'ip ecmp load-balance resilient disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_resilient_disable(
            self):
        """
        Disable resilient hashing for load balancing

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance resilient disable

        """

        cmd = [
            'no ip ecmp load-balance resilient disable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sftp_server_enable(
            self):
        """
        Enable sftp server.

        This function runs the following vtysh command:

        ::

            # sftp server enable

        """

        cmd = [
            'sftp server enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_sftp_server_enable(
            self):
        """
        Disable sftp server.

        This function runs the following vtysh command:

        ::

            # no sftp server enable

        """

        cmd = [
            'no sftp server enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server(
            self, host):
        """
        NTP Association configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host}

        :param host: NTP Association name or IPv4 Address.
        """

        cmd = [
            'ntp server {host}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_server(
            self, host):
        """
        Remove NTP association

        This function runs the following vtysh command:

        ::

            # no ntp server {host}

        :param host: NTP Association name or IPv4 Address.
        """

        cmd = [
            'no ntp server {host}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server_prefer(
            self, host):
        """
        Add NTP Association preference configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host} prefer

        :param host: NTP Association name or IPv4 Address.
        """

        cmd = [
            'ntp server {host} prefer'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server_key_id(
            self, host, key_id):
        """
        Add NTP Key ID

        This function runs the following vtysh command:

        ::

            # ntp server {host} key-id {key_id}

        :param host: NTP Association name or IPv4 Address.
        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = [
            'ntp server {host} key-id {key_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server_version(
            self, host, version):
        """
        Add NTP Association version configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host} version {version}

        :param host: NTP Association name or IPv4 Address.
        :param version: WORD  Version can be 3 or 4
        """

        cmd = [
            'ntp server {host} version {version}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_authentication_enable(
            self):
        """
        Enable NTP Authentication configuration

        This function runs the following vtysh command:

        ::

            # ntp authentication enable

        """

        cmd = [
            'ntp authentication enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_authentication_enable(
            self):
        """
        Disable NTP Authentication configuration

        This function runs the following vtysh command:

        ::

            # no ntp authentication enable

        """

        cmd = [
            'no ntp authentication enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_authentication_key_md5(
            self, key_id, password):
        """
        Add NTP Authentication Key

        This function runs the following vtysh command:

        ::

            # ntp authentication-key {key_id} md5 {password}

        :param key_id: WORD  NTP Key Number between 1-65534
        :param password: WORD  NTP MD5 Password <8-16> chars
        """

        cmd = [
            'ntp authentication-key {key_id} md5 {password}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_authentication_key(
            self, key_id):
        """
        Remove NTP Authentication Key

        This function runs the following vtysh command:

        ::

            # no ntp authentication-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = [
            'no ntp authentication-key {key_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_trusted_key(
            self, key_id):
        """
        Add NTP Trusted Key

        This function runs the following vtysh command:

        ::

            # ntp trusted-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = [
            'ntp trusted-key {key_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_trusted_key(
            self, key_id):
        """
        Remove NTP Trusted Key

        This function runs the following vtysh command:

        ::

            # no ntp trusted-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        """

        cmd = [
            'no ntp trusted-key {key_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def logging(
            self, remote_host, transport='', severity=''):
        """
        Configure Syslog Server

        This function runs the following vtysh command:

        ::

            # logging {remote_host}

        :param remote_host: IPv4 or IPv6 or Host name of syslog server
        :param transport: Optional : Transport protocol and port used to send
            syslog.  Currently we support only tcp and udp.  Example tcp 1049
        :param severity: Optional : Filter syslog messages using severity.
            Only messages with severity higher than or equal to the specified
            severity will be sent to the remote host.  Example severity debug
        """

        cmd = [
            'logging {remote_host}'
        ]

        if transport:
            cmd.append(
                '{}{{transport}}{}'.format(
                    '', ''
                )
            )

        if severity:
            cmd.append(
                '{}{{severity}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_logging(
            self, remote_host, transport='', severity=''):
        """
        Remove Syslog Server Configuration

        This function runs the following vtysh command:

        ::

            # no logging {remote_host}

        :param remote_host: IPv4 or IPv6 or Host name of syslog server
        :param transport: Optional : Transport protocol and port used to send
            syslog.   Currently we support only tcp and udp.  Example tcp 1049
        :param severity: Optional : Filter syslog messages using severity.
            Only messages with severity higher than or equal to the specified
            severity will be sent to the remote host.  Example severity debug
        """

        cmd = [
            'no logging {remote_host}'
        ]

        if transport:
            cmd.append(
                '{}{{transport}}{}'.format(
                    '', ''
                )
            )

        if severity:
            cmd.append(
                '{}{{severity}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlog_daemon(
            self, daemon, destination, severity):
        """
        Configure the daemon

        This function runs the following vtysh command:

        ::

            # vlog daemon {daemon} {destination} {severity}

        :param daemon: daemon name
        :param destination: configure the log level of destination
        :param severity: severity level
        """

        cmd = [
            'vlog daemon {daemon} {destination} {severity}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlog_feature(
            self, feature, destination, severity):
        """
        Configure the feature

        This function runs the following vtysh command:

        ::

            # vlog feature {feature} {destination} {severity}

        :param feature: feature name
        :param destination: configure the log level of destination
        :param severity: severity level
        """

        cmd = [
            'vlog feature {feature} {destination} {severity}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_community(
            self, community_name):
        """
        Configure SNMP community names

        This function runs the following vtysh command:

        ::

            # snmp-server community {community_name}

        :param community_name: Configured Community names
        """

        cmd = [
            'snmp-server community {community_name}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_community(
            self, community_name=''):
        """
        Unconfigure SNMP community names

        This function runs the following vtysh command:

        ::

            # no snmp-server community

        :param community_name: Unconfigured community names
        """

        cmd = [
            'no snmp-server community'
        ]

        if community_name:
            cmd.append(
                '{}{{community_name}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_system_contact(
            self, system_contact):
        """
        Configure SNMP system contact information

        This function runs the following vtysh command:

        ::

            # snmp-server system-contact {system_contact}

        :param system_contact: Configured System contact information
        """

        cmd = [
            'snmp-server system-contact {system_contact}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_system_contact(
            self, system_contact=''):
        """
        Unconfigure SNMP contact information

        This function runs the following vtysh command:

        ::

            # no snmp-server system-contact

        :param system_contact: Unconfigure system contact information
        """

        cmd = [
            'no snmp-server system-contact'
        ]

        if system_contact:
            cmd.append(
                '{}{{system_contact}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_system_location(
            self, system_location):
        """
        Configure SNMP system location information

        This function runs the following vtysh command:

        ::

            # snmp-server system-location {system_location}

        :param system_location: Configured System location information
        """

        cmd = [
            'snmp-server system-location {system_location}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_system_location(
            self, system_location=''):
        """
        Unconfigure SNMP location information

        This function runs the following vtysh command:

        ::

            # no snmp-server system-location

        :param system_location: Unconfigure system location information
        """

        cmd = [
            'no snmp-server system-location'
        ]

        if system_location:
            cmd.append(
                '{}{{system_location}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_system_description(
            self, system_description):
        """
        Configure SNMP system description

        This function runs the following vtysh command:

        ::

            # snmp-server system-description                {system_description}  # noqa

        :param system_description: Configured System description
        """

        cmd = [
            'snmp-server system-description                {system_description}'  # noqa
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_system_description(
            self, system_desription=''):
        """
        Unconfigure SNMP system description

        This function runs the following vtysh command:

        ::

            # no snmp-server system-description

        :param system_desription: Unconfigure system description
        """

        cmd = [
            'no snmp-server system-description'
        ]

        if system_desription:
            cmd.append(
                '{}{{system_desription}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_host_trap_version(
            self, host_ip_address, snmp_version, community='',
            community_name='', port='', snmp_port=''):
        """
        Configure SNMP server information for trap receiver

        This function runs the following vtysh command:

        ::

            # snmp-server host {host_ip_address} trap version                             {snmp_version}  # noqa

        :param host_ip_address: Configured host ip address for trap receiver
        :param snmp_version: Configured snmp version for receiver
        :param community: Configured snmp community name for trap
            receiver
        :param community-name: Configured snmp community name for trap
            receiver
        :param port: Configured snmp port for trap receiver
        :param snmp-port: Configured snmp port for trap receiver
        """  # noqa

        cmd = [
            'snmp-server host {host_ip_address} trap version                             {snmp_version}'  # noqa
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community-name:
            cmd.append(
                '{}{{community-name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp-port:
            cmd.append(
                '{}{{snmp-port}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_host_trap_version(
            self, host_ip_address, snmp_version, community='',
            community_name='', port='', snmp_port=''):
        """
        Unconfigure SNMP server information for trap receiver

        This function runs the following vtysh command:

        ::

            # no snmp-server host {host_ip_address} trap                             version {snmp_version}  # noqa

        :param host_ip_address: Unconfigured host ip address for trap
            receiver
        :param snmp_version: Unconfigured snmp version for receiver
        :param community: Unconfigured snmp community name for trap
            receiver
        :param community-name: Unconfigured snmp community name for trap
            receiver
        :param port: Unconfigured snmp port for trap receiver
        :param snmp-port: Unconfigured snmp port for trap receiver
        """  # noqa

        cmd = [
            'no snmp-server host {host_ip_address} trap                             version {snmp_version}'  # noqa
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community-name:
            cmd.append(
                '{}{{community-name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp-port:
            cmd.append(
                '{}{{snmp-port}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_inform_trap_version(
            self, host_ip_address, snmp_version, community='',
            community_name='', port='', snmp_port=''):
        """
        Configure SNMP server information for notifications

        This function runs the following vtysh command:

        ::

            # snmp-server inform {host_ip_address} trap version                             {snmp_version}  # noqa

        :param host_ip_address: Configured host ip address for notifications
        :param snmp_version: Configured snmp version for notifications
        :param community: Configured snmp community name for
            notifications
        :param community-name: Configured snmp community name for
            notifications
        :param port: Configured snmp port for notifications
        :param snmp-port: Configured snmp port for notifications
        """  # noqa

        cmd = [
            'snmp-server inform {host_ip_address} trap version                             {snmp_version}'  # noqa
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community-name:
            cmd.append(
                '{}{{community-name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp-port:
            cmd.append(
                '{}{{snmp-port}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_inform_trap_version(
            self, host_ip_address, snmp_version, community='',
            community_name='', port='', snmp_port=''):
        """
        Unconfigure SNMP server information for notifications

        This function runs the following vtysh command:

        ::

            # no snmp-server inform {host_ip_address} trap                            version {snmp_version}  # noqa

        :param host_ip_address: Unconfigured host ip address for
            notifications
        :param snmp_version: Unconfigured snmp version for notifications
        :param community: Unconfigured snmp community name for
            notifications
        :param community-name: Unconfigured snmp community name for
            notifications
        :param port: Unconfigured snmp port for notifications
        :param snmp-port: Unconfigured snmp port for notifications
        """  # noqa

        cmd = [
            'no snmp-server inform {host_ip_address} trap                            version {snmp_version}'  # noqa
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community-name:
            cmd.append(
                '{}{{community-name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp-port:
            cmd.append(
                '{}{{snmp-port}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmpv3_user(
            self, user_name):
        """
        Configure SNMPv3 user name

        This function runs the following vtysh command:

        ::

            # snmpv3 user {user-name}

        :param user-name: Configured user-name for SNMPv3
        """

        cmd = [
            'snmpv3 user {user-name}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmpv3_username(
            self, user_name):
        """
        Unconfigure SNMPv3 user name

        This function runs the following vtysh command:

        ::

            # no snmpv3 username {user-name}

        :param user-name: Unconfigured SNMPv3 user name
        """

        cmd = [
            'no snmpv3 username {user-name}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmpv3_user_auth_auth_pass(
            self, user_name, auth_protocol, auth_password):
        """
        Configure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password}  # noqa

        :param user-name: Configured user-name for SNMPv3
        :param auth-protocol: Configured auth protocol for SNMPv3 user
        :param auth-password: Configured auth password for SNMPv3 user
        """  # noqa

        cmd = [
            'snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password}'  # noqa
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmpv3_user_auth_auth_pass(
            self, user_name, auth_protocol, auth_password):
        """
        Unconfigure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # no snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password}  # noqa

        :param user-name: Unconfigured user-name for SNMPv3
        :param auth-protocol: Unconfigured auth protocol for SNMPv3 user
        :param auth-password: Unconfigured auth password for SNMPv3 user
        """  # noqa

        cmd = [
            'no snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password}'  # noqa
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def snmpv3_user_auth_auth_pass_priv_priv_pass(
            self, user_name, auth_protocol, auth_password,
            priv_protocol, priv_password):
        """
        Configure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password} priv {priv-protocol}                             priv-pass {priv-password}  # noqa

        :param user-name: Configured user-name for SNMPv3
        :param auth-protocol: Configured auth protocol for SNMPv3 user
        :param auth-password: Configured auth password for SNMPv3 user
        :param priv-protocol: Configured priv protocol for SNMPv3 user
        :param priv-password: Configured priv password for SNMPv3 user
        """  # noqa

        cmd = [
            'snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password} priv {priv-protocol}                             priv-pass {priv-password}'  # noqa
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmpv3_user_auth_auth_pass_priv_priv_pass(
            self, user_name, auth_protocol, auth_password,
            priv_protocol, priv_password):
        """
        Unconfigure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # no snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password} priv {priv-protocol}                             priv-pass {priv-password}  # noqa

        :param user-name: Unconfigured user-name for SNMPv3
        :param auth-protocol: Unconfigured auth protocol for SNMPv3 user
        :param auth-password: Unconfigured auth password for SNMPv3 user
        :param priv-protocol: Unconfigured priv protocol for SNMPv3 user
        :param priv-password: Unconfigured priv password for SNMPv3 user
        """  # noqa

        cmd = [
            'no snmpv3 user {user-name} auth {auth-protocol}                             auth-pass {auth-password} priv {priv-protocol}                             priv-pass {priv-password}'  # noqa
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class RouteMap(ContextManager):
    """
    Route-map configuration

    pre_commands:

    ::

            ['config terminal', 'route-map {routemap_name} {permission} {seq}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, routemap_name, permission, seq):
        self.enode = enode
        self.routemap_name = routemap_name
        self.permission = permission
        self.seq = seq

    def __enter__(self):
        commands = """\
            config terminal
            route-map {routemap_name} {permission} {seq}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def description(
            self, description):
        """
        Set description

        This function runs the following vtysh command:

        ::

            # description {description}

        :param description: LINE  Comment describing this route-map rule
        """

        cmd = [
            'description {description}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_description(
            self, description):
        """
        Unset description

        This function runs the following vtysh command:

        ::

            # no description {description}

        :param description: LINE  Comment describing this route-map rule
        """

        cmd = [
            'no description {description}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def match_ip_address_prefix_list(
            self, prefix_name):
        """
        Set prefix-list

        This function runs the following vtysh command:

        ::

            # match ip address prefix-list {prefix_name}

        :param prefix_name: WORD  IP prefix-list name
        """

        cmd = [
            'match ip address prefix-list {prefix_name}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_match_ip_address_prefix_list(
            self, prefix_name=''):
        """
        Unset prefix-list

        This function runs the following vtysh command:

        ::

            # no match ip address prefix-list

        :param prefix_name: WORD  IP prefix-list name
        """

        cmd = [
            'no match ip address prefix-list'
        ]

        if prefix_name:
            cmd.append(
                '{}{{prefix_name}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def set_metric(
            self, metric):
        """
        Set metric

        This function runs the following vtysh command:

        ::

            # set metric {metric}

        :param metric: <0-4294967295>  Metric value
        """

        cmd = [
            'set metric {metric}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_set_metric(
            self, metric=''):
        """
        Unset metric

        This function runs the following vtysh command:

        ::

            # no set metric

        :param metric: <0-4294967295>  Metric value
        """

        cmd = [
            'no set metric'
        ]

        if metric:
            cmd.append(
                '{}{{metric}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def set_community(
            self, community):
        """
        Set community

        This function runs the following vtysh command:

        ::

            # set community {community}

        :param community: AA:NN  Community number in aa:nn format or local-AS
            \|no-advertise\|no-export\|internet or additive
        """

        cmd = [
            'set community {community}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_set_community(
            self, community=''):
        """
        Unset community

        This function runs the following vtysh command:

        ::

            # no set community

        :param community: AA:NN  Community number in aa:nn format orlocal-AS
            \|no-advertise\|no-export\|internet or additive
        """

        cmd = [
            'no set community'
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigInterface(ContextManager):
    """
    Interface configuration.

    pre_commands:

    ::

            ['config terminal', 'interface {port}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, portlbl):
        self.enode = enode
        self.port = enode.ports.get(portlbl, portlbl)

    def __enter__(self):
        commands = """\
            config terminal
            interface {port}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
            self, ipv4):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'ip address {ipv4} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
            self, ipv4):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'no ip address {ipv4} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
            self, ipv6):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def routing(
            self):
        """
        Configure interface as L3.

        This function runs the following vtysh command:

        ::

            # routing

        """

        cmd = [
            'routing'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_routing(
            self):
        """
        Unconfigure interface as L3.

        This function runs the following vtysh command:

        ::

            # no routing

        """

        cmd = [
            'no routing'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = [
            'shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = [
            'no shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_access(
            self, vlan_id):
        """
        Access configuration

        This function runs the following vtysh command:

        ::

            # vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'vlan access {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_access(
            self, vlan_id):
        """
        Remove vlan access

        This function runs the following vtysh command:

        ::

            # no vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'no vlan access {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_allowed(
            self, vlan_id):
        """
        Allow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'vlan trunk allowed {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_allowed(
            self, vlan_id):
        """
        Disallow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'no vlan trunk allowed {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native_tag(
            self):
        """
        Tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native tag

        """

        cmd = [
            'vlan trunk native tag'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native_tag(
            self):
        """
        Remove tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native tag

        """

        cmd = [
            'no vlan trunk native tag'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native(
            self, vlan_id):
        """
        Native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'vlan trunk native {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native(
            self, vlan_id):
        """
        Remove native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'no vlan trunk native {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_port_id(
            self, port_id):
        """
        Set port ID used in LACP negotiation.

        This function runs the following vtysh command:

        ::

            # lacp port-id {port_id}

        :param port_id: <1-65535>  .The range is 1 to 65535
        """

        cmd = [
            'lacp port-id {port_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_dead_interval(
            self, dead_timer):
        """
        Configure ospf dead_timer

        This function runs the following vtysh command:

        ::

            # ip ospf dead-interval {dead_timer}

        :param dead_timer: <1-65535>  dead_timer range
        """

        cmd = [
            'ip ospf dead-interval {dead_timer}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_hello_interval(
            self, hello_timer):
        """
        Configure ospf hello_timer

        This function runs the following vtysh command:

        ::

            # ip ospf hello-interval {hello_timer}

        :param hello_timer: <1-65535>  hello_timer range
        """

        cmd = [
            'ip ospf hello-interval {hello_timer}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_port_priority(
            self, port_priority):
        """
        Set port priority is used in LACP negotiation.

        This function runs the following vtysh command:

        ::

            # lacp port-priority {port_priority}

        :param port_priority: <1-65535>  The range is 1 to 65535
        """

        cmd = [
            'lacp port-priority {port_priority}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lag(
            self, lag_id):
        """
        Add the current interface to link aggregation.

        This function runs the following vtysh command:

        ::

            # lag {lag_id}

        :param lag_id: <1-2000>  LAG number ranges from 1 to 2000
        """

        cmd = [
            'lag {lag_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lag(
            self, lag_id):
        """
        Remove the current interface to link aggregation.

        This function runs the following vtysh command:

        ::

            # no lag {lag_id}

        :param lag_id: <1-2000>  LAG number ranges from 1 to 2000
        """

        cmd = [
            'no lag {lag_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_transmission(
            self):
        """
        Set the transmission on lldp.

        This function runs the following vtysh command:

        ::

            # lldp transmission

        """

        cmd = [
            'lldp transmission'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_transmission(
            self):
        """
        Un-set the transmission on lldp.

        This function runs the following vtysh command:

        ::

            # no lldp transmission

        """

        cmd = [
            'no lldp transmission'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_reception(
            self):
        """
        Set the reception on lldp.

        This function runs the following vtysh command:

        ::

            # lldp reception

        """

        cmd = [
            'lldp reception'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_reception(
            self):
        """
        Un-set the reception on lldp.

        This function runs the following vtysh command:

        ::

            # no lldp reception

        """

        cmd = [
            'no lldp reception'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def udld_enable(
            self):
        """
        Enable UDLD in the interface.

        This function runs the following vtysh command:

        ::

            # udld enable

        """

        cmd = [
            'udld enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_udld_enable(
            self):
        """
        Disable UDLD in the interface.

        This function runs the following vtysh command:

        ::

            # no udld enable

        """

        cmd = [
            'no udld enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def udld_interval(
            self, interval):
        """
        Set the packet interval

        This function runs the following vtysh command:

        ::

            # udld interval {interval}

        :param interval: <100-10000> Allowed is 100 ms to 10,000 ms
        """

        cmd = [
            'udld interval {interval}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def udld_retries(
            self, retries):
        """
        Set the retries

        This function runs the following vtysh command:

        ::

            # udld retries {retries}

        :param retries: <3-10> Allowed is from 3 to 10 retries.
        """

        cmd = [
            'udld retries {retries}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def udld_mode(
            self, mode):
        """
        Set the operation mode

        This function runs the following vtysh command:

        ::

            # udld mode {mode}

        :param mode: <forward_then_verify | verify_then_forward>
        """

        cmd = [
            'udld mode {mode}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_enable(
            self):
        """
        Enable sflow feature on interface

        This function runs the following vtysh command:

        ::

            # sflow enable

        """

        cmd = [
            'sflow enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_enable(
            self):
        """
        Disable sflow feature on interface

        This function runs the following vtysh command:

        ::

            # no sflow enable

        """

        cmd = [
            'no sflow enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigSubinterface(ContextManager):
    """
    Sub-Interface configuration.

    pre_commands:

    ::

            ['config terminal', 'interface {port}.{subint}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, portlbl, subint):
        self.enode = enode
        self.port = enode.ports.get(portlbl, portlbl)
        self.subint = subint

    def __enter__(self):
        commands = """\
            config terminal
            interface {port}.{subint}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Subinterface IP address.
        """

        cmd = [
            'ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Subinterface IP address.
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Subinterface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Subinterface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def encapsulation_dot1_q(
            self, vlan_id):
        """
        Set encapsulation type for a subinterface

        This function runs the following vtysh command:

        ::

            # encapsulation dot1Q {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier.
        """

        cmd = [
            'encapsulation dot1Q {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_encapsulation_dot1_q(
            self, vlan_id):
        """
        Unset encapsulation type for a subinterface

        This function runs the following vtysh command:

        ::

            # no encapsulation dot1Q {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier.
        """

        cmd = [
            'no encapsulation dot1Q {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable a subinterface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = [
            'shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable a subinterface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = [
            'no shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceVlan(ContextManager):
    """
    VLAN configuration.

    pre_commands:

    ::

            ['config terminal', 'interface vlan {vlan_id}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, vlan_id):
        self.enode = enode
        self.vlan_id = vlan_id

    def __enter__(self):
        commands = """\
            config terminal
            interface vlan {vlan_id}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
            self, ipv4):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'ip address {ipv4} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
            self, ipv4):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'no ip address {ipv4} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
            self, ipv6):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = [
            'shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = [
            'no shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceLoopback(ContextManager):
    """
    Loopback interface configuration.

    pre_commands:

    ::

            ['config terminal', 'interface loopback {loopback_id}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, loopback_id):
        self.enode = enode
        self.loopback_id = loopback_id

    def __enter__(self):
        commands = """\
            config terminal
            interface loopback {loopback_id}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IPv4 address for loopback

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Loopback IP address.
        """

        cmd = [
            'ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IPv4 address for loopback

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Loopback IP address.
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address on Loopback

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Loopback IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address on loopback interface

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Loopback IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceLag(ContextManager):
    """
    Configure link-aggregation parameters.

    pre_commands:

    ::

            ['config terminal', 'interface lag {lag}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, lag):
        self.enode = enode
        self.lag = lag

    def __enter__(self):
        commands = """\
            config terminal
            interface lag {lag}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_address(
            self, ipv4):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
            self, ipv4):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
            self, ipv4):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'ip address {ipv4} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
            self, ipv4):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        """

        cmd = [
            'no ip address {ipv4} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
            self, ipv6):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
            self, ipv6):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'ipv6 address {ipv6} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
            self, ipv6):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        """

        cmd = [
            'no ipv6 address {ipv6} secondary'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = [
            'shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = [
            'no shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def routing(
            self):
        """
        Configure interface as L3.

        This function runs the following vtysh command:

        ::

            # routing

        """

        cmd = [
            'routing'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_routing(
            self):
        """
        Unconfigure interface as L3.

        This function runs the following vtysh command:

        ::

            # no routing

        """

        cmd = [
            'no routing'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_access(
            self, vlan_id):
        """
        Access configuration

        This function runs the following vtysh command:

        ::

            # vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'vlan access {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_access(
            self, vlan_id):
        """
        Remove vlan access

        This function runs the following vtysh command:

        ::

            # no vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'no vlan access {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_allowed(
            self, vlan_id):
        """
        Allow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'vlan trunk allowed {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_allowed(
            self, vlan_id):
        """
        Disallow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'no vlan trunk allowed {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native_tag(
            self):
        """
        Tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native tag

        """

        cmd = [
            'vlan trunk native tag'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native_tag(
            self):
        """
        Remove tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native tag

        """

        cmd = [
            'no vlan trunk native tag'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native(
            self, vlan_id):
        """
        Native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'vlan trunk native {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native(
            self, vlan_id):
        """
        Remove native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        """

        cmd = [
            'no vlan trunk native {vlan_id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_mode_passive(
            self):
        """
        Sets an interface as LACP passive.

        This function runs the following vtysh command:

        ::

            # lacp mode passive

        """

        cmd = [
            'lacp mode passive'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_mode_passive(
            self):
        """
        Sets an LACP passive interface off.

        This function runs the following vtysh command:

        ::

            # no lacp mode passive

        """

        cmd = [
            'no lacp mode passive'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_mode_active(
            self):
        """
        Sets an interface as LACP active.

        This function runs the following vtysh command:

        ::

            # lacp mode active

        """

        cmd = [
            'lacp mode active'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_mode_active(
            self):
        """
        Sets an LACP active interface off.

        This function runs the following vtysh command:

        ::

            # no lacp mode active

        """

        cmd = [
            'no lacp mode active'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_fallback(
            self):
        """
        Enable LACP fallback mode.

        This function runs the following vtysh command:

        ::

            # lacp fallback

        """

        cmd = [
            'lacp fallback'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def hash_l2_src_dst(
            self):
        """
        Base the hash on l2-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l2-src-dst

        """

        cmd = [
            'hash l2-src-dst'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def hash_l3_src_dst(
            self):
        """
        Base the hash on l3-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l3-src-dst

        """

        cmd = [
            'hash l3-src-dst'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def hash_l4_src_dst(
            self):
        """
        Base the hash on l4-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l4-src-dst

        """

        cmd = [
            'hash l4-src-dst'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_rate_fast(
            self):
        """
        Set LACP heartbeats are requested at the rate of one per second.

        This function runs the following vtysh command:

        ::

            # lacp rate fast

        """

        cmd = [
            'lacp rate fast'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_rate_fast(
            self):
        """
        Set LACP heartbeats slow which is once every  30 seconds.

        This function runs the following vtysh command:

        ::

            # no lacp rate fast

        """

        cmd = [
            'no lacp rate fast'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigInterfaceMgmt(ContextManager):
    """
    Configure management interface.

    pre_commands:

    ::

            ['config terminal', 'interface mgmt']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            config terminal
            interface mgmt
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def ip_static(
            self, ip):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip static {ip}

        :param ip: Interface IP (ipv4 or ipv6) address.
        """

        cmd = [
            'ip static {ip}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_static(
            self, ip):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip static {ip}

        :param ip: Interface IP (ipv4 or ipv6) address.
        """

        cmd = [
            'no ip static {ip}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def default_gateway(
            self, gateway):
        """
        Configure the Default gateway address (IPv4 and IPv6)

        This function runs the following vtysh command:

        ::

            # default-gateway {gateway}

        :param gateway: IP (ipv4 or ipv6) address.
        """

        cmd = [
            'default-gateway {gateway}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_default_gateway(
            self, gateway):
        """
        Remove the Default gateway address (IPv4 and IPv6)

        This function runs the following vtysh command:

        ::

            # no default-gateway {gateway}

        :param gateway: IP (ipv4 or ipv6) address.
        """

        cmd = [
            'no default-gateway {gateway}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def nameserver(
            self, primary_nameserver, secondary_nameserver=''):
        """
        Configure the nameserver

        This function runs the following vtysh command:

        ::

            # nameserver {primary_nameserver}

        :param primary_nameserver: Primary nameserver (ipv4 or ipv6) address.
        :param secondary_nameserver: Secondary nameserver (ipv4 or ipv6)
            address.
        """

        cmd = [
            'nameserver {primary_nameserver}'
        ]

        if secondary_nameserver:
            cmd.append(
                '{}{{secondary_nameserver}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_nameserver(
            self, primary_nameserver, secondary_nameserver=''):
        """
        Configure the nameserver

        This function runs the following vtysh command:

        ::

            # no nameserver {primary_nameserver}

        :param primary_nameserver: Primary nameserver (ipv4 or ipv6) address.
        :param secondary_nameserver: Secondary nameserver (ipv4 or ipv6)
            address.
        """

        cmd = [
            'no nameserver {primary_nameserver}'
        ]

        if secondary_nameserver:
            cmd.append(
                '{}{{secondary_nameserver}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def ip_dhcp(
            self):
        """
        Set the mode as dhcp.

        This function runs the following vtysh command:

        ::

            # ip dhcp

        """

        cmd = [
            'ip dhcp'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigRouterOspf(ContextManager):
    """
    OSPF configuration.

    pre_commands:

    ::

            ['config terminal', 'router ospf']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            config terminal
            router ospf
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def router_id(
            self, id):
        """
        Specifies the OSPF router-ID for a OSPF Router

        This function runs the following vtysh command:

        ::

            # router-id {id}

        :param id: <A.B.C.D> IPv4 address
        """

        cmd = [
            'router-id {id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_router_id(
            self, id):
        """
        Specifies the OSPF router-ID for a OSPF Router

        This function runs the following vtysh command:

        ::

            # no router-id {id}

        :param id: <A.B.C.D> IPv4 address
        """

        cmd = [
            'no router-id {id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def max_metric_router_lsa(
            self):
        """
        Configures the router as stub router

        This function runs the following vtysh command:

        ::

            # max-metric router-lsa

        """

        cmd = [
            'max-metric router-lsa'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def network_area(
            self, network, area):
        """
        Adds the announcement network for OSPF

        This function runs the following vtysh command:

        ::

            # network {network} area {area}

        :param network: <A.B.C.D/M> IPv4 address with the prefix len
        :param area: <0-4228250625 | A.B.C.D> Area-id range
        """

        cmd = [
            'network {network} area {area}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_network_area(
            self, network, area):
        """
        Removes the announcement network for OSPF

        This function runs the following vtysh command:

        ::

            # no network {network} area {area}

        :param network: <A.B.C.D/M> IPv4 address with the prefix length
        :param area: <0-4228250625 | A.B.C.D> Area-id range
        """

        cmd = [
            'no network {network} area {area}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigRouterBgp(ContextManager):
    """
    BGP configuration.

    pre_commands:

    ::

            ['config terminal', 'router bgp {asn}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, asn):
        self.enode = enode
        self.asn = asn

    def __enter__(self):
        commands = """\
            config terminal
            router bgp {asn}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def bgp_router_id(
            self, id):
        """
        Specifies the BGP router-ID for a BGP Router

        This function runs the following vtysh command:

        ::

            # bgp router-id {id}

        :param id: <A.B.C.D> IPv4 address
        """

        cmd = [
            'bgp router-id {id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_bgp_router_id(
            self, id):
        """
        Removes the BGP router-ID for a BGP Router

        This function runs the following vtysh command:

        ::

            # no bgp router-id {id}

        :param id: <A.B.C.D> IPv4 address
        """

        cmd = [
            'no bgp router-id {id}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def bgp_fast_external_failover(
            self):
        """
        Immediately reset session if a link to a directly connected external
        peer goes down

        This function runs the following vtysh command:

        ::

            # bgp fast-external-failover

        """

        cmd = [
            'bgp fast-external-failover'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_bgp_fast_external_failover(
            self):
        """
        Disables BGP fast external failover

        This function runs the following vtysh command:

        ::

            # no bgp fast-external-failover

        """

        cmd = [
            'no bgp fast-external-failover'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def network(
            self, network):
        """
        Adds the announcement network for BGP

        This function runs the following vtysh command:

        ::

            # network {network}

        :param network: <A.B.C.D/M> IPv4 address with the prefix len
        """

        cmd = [
            'network {network}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_network(
            self, network):
        """
        Removes the announcement network for BGP

        This function runs the following vtysh command:

        ::

            # no network {network}

        :param network: <A.B.C.D/M> IPv4 address with the prefix length
        """

        cmd = [
            'no network {network}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def maximum_paths(
            self, num):
        """
        Sets the maximum number of paths for a BGP route

        This function runs the following vtysh command:

        ::

            # maximum-paths {num}

        :param num: <1-255> Maximum number of paths. Default is 1
        """

        cmd = [
            'maximum-paths {num}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_maximum_paths(
            self, num):
        """
        Set the max number of paths to the default value of 1

        This function runs the following vtysh command:

        ::

            # no maximum-paths {num}

        :param num: <1-255> Maximum number of paths. Default is 1
        """

        cmd = [
            'no maximum-paths {num}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def timers_bgp(
            self, keepalive, hold):
        """
        Sets the keepalive interval and hold time for a BGP router

        This function runs the following vtysh command:

        ::

            # timers bgp {keepalive} {hold}

        :param keepalive: <0-65535> Keepalive interval in seconds. Default is
            60
        :param hold: <0 - 65535> Hold time in seconds. Default is 180
        """

        cmd = [
            'timers bgp {keepalive} {hold}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_timers_bgp(
            self, keepalive='', hold=''):
        """
        Sets the default values for keepalive interval and hold time for a BGP
        router

        This function runs the following vtysh command:

        ::

            # no timers bgp

        :param keepalive: <0 - 65535> Keepalive interval in seconds. Default
            is 60
        :param hold: <0 - 65535> Hold time in seconds. Default is 180
        """

        cmd = [
            'no timers bgp'
        ]

        if keepalive:
            cmd.append(
                '{}{{keepalive}}{}'.format(
                    '', ''
                )
            )

        if hold:
            cmd.append(
                '{}{{hold}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_remote_as(
            self, ip, asn):
        """
        Configures a BGP neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {ip} remote-as {asn}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param asn: <1 - 4294967295> Neighbor AS number. Ranges from 1 to
            4294967295
        """

        cmd = [
            'neighbor {ip} remote-as {asn}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor(
            self, ip):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'no neighbor {ip}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_route_map(
            self, ip, route_name, action):
        """
        Configures a BGP neighbor route-map

        This function runs the following vtysh command:

        ::

            # neighbor {ip} route-map {route_name} {action}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param route_name: WORD  Name of route map
        :param action: export  Apply map to routes coming
            from a Route-Server
            client
            import  Apply map to routes going into
            a Route-Server client's
            table
            in      Apply map to incoming routes
            out     Apply map to
            outbound routes
        """

        cmd = [
            'neighbor {ip} route-map {route_name} {action}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_route_map(
            self, ip, route_name, action):
        """
        Unconfigures a BGP neighbor route-map

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} route-map {route_name} {action}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param route_name: WORD  Name of route map
        :param action: export  Apply map to routes coming
            from a Route-Server
            client
            import  Apply map to routes going into
            a Route-Server client's
            table
            in      Apply map to incoming routes
            out     Apply map to
            outbound routes
        """

        cmd = [
            'no neighbor {ip} route-map {route_name} {action}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_prefix_list(
            self, peer, prefix_name, filter_direction=''):
        """
        Applies a prefix-list to the neighbor to filter updates to and from the
        neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {peer} prefix-list {prefix_name}

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param prefix_name: <WORD> The name of a prefix list
        :param filter_direction: <in|out> Filters incoming/outgoing routes
        """

        cmd = [
            'neighbor {peer} prefix-list {prefix_name}'
        ]

        if filter_direction:
            cmd.append(
                '{}{{filter_direction}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_prefix_list(
            self, peer, prefix_name, filter_direction=''):
        """
        Remove a prefix-list filter from the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {peer} prefix-list {prefix_name}

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param prefix_name: <WORD> The name of a prefix list
        :param filter_direction: <in|out> Filters incoming/outgoing routes
        """

        cmd = [
            'no neighbor {peer} prefix-list {prefix_name}'
        ]

        if filter_direction:
            cmd.append(
                '{}{{filter_direction}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_description(
            self, ip, text):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {ip} description {text}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param text: Description of the peer router. String of maximum length
            80 chars
        """

        cmd = [
            'neighbor {ip} description {text}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_description(
            self, ip, text=''):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} description

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param text: Description of the peer router.String of maximum length
            80 chars
        """

        cmd = [
            'no neighbor {ip} description'
        ]

        if text:
            cmd.append(
                '{}{{text}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_password(
            self, ip, pwd):
        """
        Enables MD5 authentication on a TCP connection between BGP peers.

        This function runs the following vtysh command:

        ::

            # neighbor {ip} password {pwd}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param pwd: Password in plain text.String of maximum length 80 chars
        """

        cmd = [
            'neighbor {ip} password {pwd}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_password(
            self, ip):
        """
        Removes MD5 authentication on a TCP connection between BGP peers.

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} password

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'no neighbor {ip} password'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_timers(
            self, ip, keepalive, hold):
        """
        Sets the keepalive interval and hold time for a specific BGP peer

        This function runs the following vtysh command:

        ::

            # neighbor {ip} timers {keepalive} {hold}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param keepalive: <0 - 65535> Keepalive interval in seconds.Default is
            60
        :param hold: <0-65535> Hold time in seconds. Default is 180
        """

        cmd = [
            'neighbor {ip} timers {keepalive} {hold}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_timers(
            self, ip, keepalive='', hold=''):
        """
        Sets the default values for keepalive interval and hold time for a
        specific BGP peer

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} timers

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param keepalive: <0 - 65535> Keepalive interval in seconds.Default is
            0
        :param hold: <0 - 65535> Hold time in seconds. Default is 0
        """

        cmd = [
            'no neighbor {ip} timers'
        ]

        if keepalive:
            cmd.append(
                '{}{{keepalive}}{}'.format(
                    '', ''
                )
            )

        if hold:
            cmd.append(
                '{}{{hold}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_allowas_in(
            self, ip, val=''):
        """
        Specifies an allow-as-in occurrence number for an AS to be in the AS
        path

        This function runs the following vtysh command:

        ::

            # neighbor {ip} allowas-in

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param val: <0 - 10> Number of times BGP can allow an instance of AS
            to be in the AS_PATH
        """

        cmd = [
            'neighbor {ip} allowas-in'
        ]

        if val:
            cmd.append(
                '{}{{val}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_allowas_in(
            self, ip, val=''):
        """
        Clears the allow-as-in occurrence number for an AS to be in the AS path

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} allowas-in

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param val: <0 - 10> Number of times BGP can allow aninstance of AS to
            be in the AS_PATH
        """

        cmd = [
            'no neighbor {ip} allowas-in'
        ]

        if val:
            cmd.append(
                '{}{{val}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_remove_private_as(
            self, ip):
        """
        Removes private AS numbers from the AS pathin outbound routing updates

        This function runs the following vtysh command:

        ::

            # neighbor {ip} remove-private-AS

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'neighbor {ip} remove-private-AS'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_remove_private_as(
            self, ip):
        """
        Resets to a cleared state (default)

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} remove-private-AS

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'no neighbor {ip} remove-private-AS'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_soft_reconfiguration_inbound(
            self, ip):
        """
        Enables software-based reconfiguration to generate updates from a
        neighbor without clearing the BGP session

        This function runs the following vtysh command:

        ::

            # neighbor {ip} soft-reconfiguration inbound

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'neighbor {ip} soft-reconfiguration inbound'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_soft_reconfiguration_inbound(
            self, ip):
        """
        Resets to a cleared state (default)

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} soft-reconfiguration inbound

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'no neighbor {ip} soft-reconfiguration inbound'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_shutdown(
            self, ip):
        """
        Shuts down the neighbor. This disables the peer routerbut preserves
        neighbor configuration

        This function runs the following vtysh command:

        ::

            # neighbor {ip} shutdown

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'neighbor {ip} shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_shutdown(
            self, ip):
        """
        Re-enables the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} shutdown

        :param ip: <A.B.C.D> Neighbor IPv4 address
        """

        cmd = [
            'no neighbor {ip} shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_peer_group(
            self, ip_or_group, group=''):
        """
        Assigns a neighbor to a peer-group

        This function runs the following vtysh command:

        ::

            # neighbor {ip_or_group} peer-group

        :param ip_or_group: <A.B.C.D> Neighbor IPv4 address<X:X::X:X> Neighbor
            IPv6 address<WORD> Neighbor group
        :param group: ('Peer-group name.String of maximum length 80 chars',)
        """

        cmd = [
            'neighbor {ip_or_group} peer-group'
        ]

        if group:
            cmd.append(
                '{}{{group}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_peer_group(
            self, ip_or_group, group=''):
        """
        Removes the neighbor from the peer-group

        This function runs the following vtysh command:

        ::

            # no neighbor {ip_or_group} peer-group

        :param ip_or_group: <A.B.C.D> Neighbor IPv4 address<X:X::X:X> Neighbor
            IPv6 address<WORD> Neighbor group
        :param group: Peer-group name. String of maximum length 80 chars
        """

        cmd = [
            'no neighbor {ip_or_group} peer-group'
        ]

        if group:
            cmd.append(
                '{}{{group}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def redistribute(
            self, type):
        """
        Configures route redistribution of the specified protocol into BGP

        This function runs the following vtysh command:

        ::

            # redistribute {type}

        :param type: <connected | static | ospf>
        """

        cmd = [
            'redistribute {type}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_redistribute(
            self, type):
        """
        Unconfigures route redistribution of the specified protocol into BGP

        This function runs the following vtysh command:

        ::

            # no redistribute {type}

        :param type: <connected | static | ospf>
        """

        cmd = [
            'no redistribute {type}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigVlan(ContextManager):
    """
    VLAN configuration.

    pre_commands:

    ::

            ['config terminal', 'vlan {vlan_id}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, vlan_id):
        self.enode = enode
        self.vlan_id = vlan_id

    def __enter__(self):
        commands = """\
            config terminal
            vlan {vlan_id}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def shutdown(
            self):
        """
        Enable the VLAN.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = [
            'shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Disable the VLAN.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = [
            'no shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def description(
            self, description):
        """
        Set VLAN description

        This function runs the following vtysh command:

        ::

            # description {description}

        :param description: VLAN description.
        """

        cmd = [
            'description {description}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_description(
            self, description):
        """
        Un-set VLAN description

        This function runs the following vtysh command:

        ::

            # no description {description}

        :param description: VLAN description.
        """

        cmd = [
            'no description {description}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigTftpServer(ContextManager):
    """
    tftp-server configuration.

    pre_commands:

    ::

            ['config terminal', 'tftp-server']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            config terminal
            tftp-server
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def enable(
            self):
        """
        Enable tftp server.

        This function runs the following vtysh command:

        ::

            # enable

        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_enable`
        """

        cmd = [
            'enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        return parse_config_tftp_server_enable(result)

    def no_enable(
            self):
        """
        Disable tftp server.

        This function runs the following vtysh command:

        ::

            # no enable

        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_no_enable`
        """

        cmd = [
            'no enable'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        return parse_config_tftp_server_no_enable(result)

    def path(
            self, path):
        """
        Set Path of tftp-server

        This function runs the following vtysh command:

        ::

            # path {path}

        :param path: path of the directory
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_path`
        """

        cmd = [
            'path {path}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        return parse_config_tftp_server_path(result)

    def no_path(
            self, path):
        """
        Unset path to tftp server.

        This function runs the following vtysh command:

        ::

            # no path {path}

        :param path: path of the directory
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_no_path`
        """

        cmd = [
            'no path {path}'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        return parse_config_tftp_server_no_path(result)


class ConfigDhcpServer(ContextManager):
    """
    DHCP server configuration.

    pre_commands:

    ::

            ['config terminal', 'dhcp-server']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode):
        self.enode = enode

    def __enter__(self):
        commands = """\
            config terminal
            dhcp-server
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def range_start_ip_address_end_ip_address(
            self, range_name, start_ip, end_ip, subnet_mask='',
            broadcast_address='', tag_name='', set_name='',
            prefix_len_value='', lease_duration_value=''):
        """
        Sets DHCP dynamic configuration.

        This function runs the following vtysh command:

        ::

            # range {range_name} start-ip-address {start_ip} end-ip-address {end_ip}  # noqa

        :param range_name: DHCP range name. String of maximum length 15 chars
        :param start_ip: <A.B.C.D> Start range IPv4 address or <X:X::X:X>
            Start range IPv6 address
        :param end_ip: <A.B.C.D> End range IPv4 address or <X:X::X:X> End
            range IPv6 address
        :param subnet_mask: <A.B.C.D> Range netmask address
        :param broadcast_address: <A.B.C.D> Range broadcast address
        :param tag_name: Match tags list. Each tag length must be less than 15
            chars.
        :param set_name: Tag set name. Length must be less than 15 chars.
        :param prefix_len_value: IPV6 prefix length. <64 - 128> Configurable
            range.
        :param lease_duration_value: Range lease duration. Default value is 60
            min.
        """  # noqa

        cmd = [
            'range {range_name} start-ip-address {start_ip} end-ip-address {end_ip}'  # noqa
        ]

        if subnet_mask:
            cmd.append(
                '{}{{subnet_mask}}{}'.format(
                    ' netmask ', ''
                )
            )

        if broadcast_address:
            cmd.append(
                '{}{{broadcast_address}}{}'.format(
                    ' broadcast ', ''
                )
            )

        if tag_name:
            cmd.append(
                '{}{{tag_name}}{}'.format(
                    ' match tags ', ''
                )
            )

        if set_name:
            cmd.append(
                '{}{{set_name}}{}'.format(
                    ' set tag ', ''
                )
            )

        if prefix_len_value:
            cmd.append(
                '{}{{prefix_len_value}}{}'.format(
                    ' prefix-len ', ''
                )
            )

        if lease_duration_value:
            cmd.append(
                '{}{{lease_duration_value}}{}'.format(
                    ' lease-duration ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_range_start_ip_address_end_ip_address(
            self, range_name, start_ip, end_ip, subnet_mask='',
            broadcast_address='', tag_name='', set_name='',
            prefix_len_value='', lease_duration_value=''):
        """
        Removes DHCP dynamic configuration.

        This function runs the following vtysh command:

        ::

            # no range {range_name} start-ip-address {start_ip} end-ip-address {end_ip}   # noqa

        :param range_name: DHCP range name. String of maximum length 15 chars
        :param start_ip: <A.B.C.D> Start range IPv4 address or <X:X::X:X>
            Start range IPv6 address
        :param end_ip: <A.B.C.D> End range IPv4 address or <X:X::X:X> End
            range IPv6 address
        :param subnet_mask: <A.B.C.D> Range netmask address
        :param broadcast_address: <A.B.C.D> Range broadcast address
        :param tag_name: Match tags list. Each tag length must be less than 15
            chars.
        :param set_name: Tag set name. Length must be less than 15 chars.
        :param prefix_len_value: IPV6 prefix length. <64 - 128> Configurable
            range.
        :param lease_duration_value: Range lease duration. Default value is 60
            min.
        """  # noqa

        cmd = [
            'no range {range_name} start-ip-address {start_ip} end-ip-address {end_ip} '  # noqa
        ]

        if subnet_mask:
            cmd.append(
                '{}{{subnet_mask}}{}'.format(
                    ' netmask ', ''
                )
            )

        if broadcast_address:
            cmd.append(
                '{}{{broadcast_address}}{}'.format(
                    ' broadcast ', ''
                )
            )

        if tag_name:
            cmd.append(
                '{}{{tag_name}}{}'.format(
                    ' match tags ', ''
                )
            )

        if set_name:
            cmd.append(
                '{}{{set_name}}{}'.format(
                    ' set tag ', ''
                )
            )

        if prefix_len_value:
            cmd.append(
                '{}{{prefix_len_value}}{}'.format(
                    ' prefix-len ', ''
                )
            )

        if lease_duration_value:
            cmd.append(
                '{}{{lease_duration_value}}{}'.format(
                    ' lease-duration ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def static(
            self, ip_address, mac_address='', hostname='',
            client_id='', set_tag_names='',
            lease_duration_value=''):
        """
        Sets DHCP dynamic configuration.

        This function runs the following vtysh command:

        ::

            # static {ip_address}

        :param ip_address: <A.B.C.D> IPv4 address or <X:X::X:X> IPv6 address
        :param mac_address: <XX:XX:XX:XX:XX:XX> MAC address or <XX-XX-XX-XX-
            XX-XX> MAC addressClient MAC addresses
        :param hostname: Client hostname. Length must be less than 15 chars.
        :param client_id: Client id. Length must be less than 15 chars.
        :param set_tag_names: Set tag list names. Each tag length must be less
            than 15 chars.
        :param lease_duration_value: Range lease duration. Default value is 60
            min.
        """

        cmd = [
            'static {ip_address}'
        ]

        if mac_address:
            cmd.append(
                '{}{{mac_address}}{}'.format(
                    ' match-mac-addresses ', ''
                )
            )

        if hostname:
            cmd.append(
                '{}{{hostname}}{}'.format(
                    ' match-client-hostname ', ''
                )
            )

        if client_id:
            cmd.append(
                '{}{{client_id}}{}'.format(
                    ' match-client-id ', ''
                )
            )

        if set_tag_names:
            cmd.append(
                '{}{{set_tag_names}}{}'.format(
                    ' set tags ', ''
                )
            )

        if lease_duration_value:
            cmd.append(
                '{}{{lease_duration_value}}{}'.format(
                    ' lease-duration ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_static(
            self, ip_address, mac_address='', hostname='',
            client_id='', set_tag_names='',
            lease_duration_value=''):
        """
        Removes DHCP dynamic configuration.

        This function runs the following vtysh command:

        ::

            # no static {ip_address}

        :param ip_address: <A.B.C.D> IPv4 address or <X:X::X:X> IPv6 address
        :param mac_address: <XX:XX:XX:XX:XX:XX> MAC address or <XX-XX-XX-XX-
            XX-XX> MAC addressClient MAC addresses
        :param hostname: Client hostname Length must be less than 15 chars.
        :param client_id: Client id. Length must be less than 15 chars.
        :param set_tag_names: Set tag list names. Each tag length must be less
            than 15 chars.
        :param lease_duration_value: Range lease duration. Default value is 60
            min.
        """

        cmd = [
            'no static {ip_address}'
        ]

        if mac_address:
            cmd.append(
                '{}{{mac_address}}{}'.format(
                    ' match-mac-addresses ', ''
                )
            )

        if hostname:
            cmd.append(
                '{}{{hostname}}{}'.format(
                    ' match-client-hostname ', ''
                )
            )

        if client_id:
            cmd.append(
                '{}{{client_id}}{}'.format(
                    ' match-client-id ', ''
                )
            )

        if set_tag_names:
            cmd.append(
                '{}{{set_tag_names}}{}'.format(
                    ' set tags ', ''
                )
            )

        if lease_duration_value:
            cmd.append(
                '{}{{lease_duration_value}}{}'.format(
                    ' lease-duration ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def option_set(
            self, set_name='', option_number='', option_value='',
            tag_name='', ipv6=''):
        """
        Sets DHCP configuration values using an option name.

        This function runs the following vtysh command:

        ::

            # option set

        :param set_name: DHCP option name
        :param option-number: DHCP option number
        :param option_value: DHCP option value
        :param tag_name: Match tags list. Each tag length must be less than 15
            chars.
        :param ipv6: Enable ipv6 for the set.
        """

        cmd = [
            'option set'
        ]

        if set_name:
            cmd.append(
                '{}{{set_name}}{}'.format(
                    ' option-name ', ''
                )
            )

        if option-number:
            cmd.append(
                '{}{{option-number}}{}'.format(
                    ' option-number ', ''
                )
            )

        if option_value:
            cmd.append(
                '{}{{option_value}}{}'.format(
                    ' option-value ', ''
                )
            )

        if tag_name:
            cmd.append(
                '{}{{tag_name}}{}'.format(
                    ' match tags', ''
                )
            )

        if ipv6:
            cmd.append(
                '{}{{ipv6}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_option_set(
            self, set_name='', option_number='', option_value='',
            tag_name='', ipv6=''):
        """
        Removes DHCP configuration values using an option name.

        This function runs the following vtysh command:

        ::

            # no option set

        :param set_name: DHCP option name
        :param option-number: DHCP option number
        :param option_value: DHCP option value
        :param tag_name: Match tags list. Each tag length must be less than 15
            chars.
        :param ipv6: Enable ipv6 for the set.
        """

        cmd = [
            'no option set'
        ]

        if set_name:
            cmd.append(
                '{}{{set_name}}{}'.format(
                    ' option-name ', ''
                )
            )

        if option-number:
            cmd.append(
                '{}{{option-number}}{}'.format(
                    ' option-number ', ''
                )
            )

        if option_value:
            cmd.append(
                '{}{{option_value}}{}'.format(
                    ' option-value ', ''
                )
            )

        if tag_name:
            cmd.append(
                '{}{{tag_name}}{}'.format(
                    ' match-tags ', ''
                )
            )

        if ipv6:
            cmd.append(
                '{}{{ipv6}}{}'.format(
                    '', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def match_set_tag(
            self, tag_name, option_number='', option_name='',
            option_value=''):
        """
        Sets DHCP match configuration using an option name.

        This function runs the following vtysh command:

        ::

            # match set tag {tag_name}

        :param tag_name: DHCP match tag nameLength must be less than 15 chars.
        :param option_number: DHCP option number. <0 - 255> Configurable
            range.
        :param option_name: DHCP option name. Length must be less than 15
            chars.
        :param option_value: DHCP option value
        """

        cmd = [
            'match set tag {tag_name}'
        ]

        if option_number:
            cmd.append(
                '{}{{option_number}}{}'.format(
                    ' match-option-number ', ''
                )
            )

        if option_name:
            cmd.append(
                '{}{{option_name}}{}'.format(
                    ' match-option-name ', ''
                )
            )

        if option_value:
            cmd.append(
                '{}{{option_value}}{}'.format(
                    ' match-option-value ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_match_set_tag(
            self, tag_name, option_name='', option_number='',
            option_value=''):
        """
        Removes DHCP match configuration using an option name.

        This function runs the following vtysh command:

        ::

            # no match set tag {tag_name}

        :param tag_name: DHCP match tag nameLength must be less than 15 chars.
        :param option_name: DHCP option name. Length must be less than 15
            chars.
        :param option_number: DHCP option number. <0 - 255> Configurable
            range.
        :param option_value: DHCP option value
        """

        cmd = [
            'no match set tag {tag_name}'
        ]

        if option_name:
            cmd.append(
                '{}{{option_name}}{}'.format(
                    ' match-option-name ', ''
                )
            )

        if option_number:
            cmd.append(
                '{}{{option_number}}{}'.format(
                    ' match-option-number ', ''
                )
            )

        if option_value:
            cmd.append(
                '{}{{option_value}}{}'.format(
                    ' match-option-value ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def boot_set_file(
            self, file_name, tag_name=''):
        """
        Sets DHCP bootp options.

        This function runs the following vtysh command:

        ::

            # boot set file {file_name}

        :param file_name: DHCP boot file name
        :param tag_name: DHCP match tag name. Length must be less than 15
            chars.
        """

        cmd = [
            'boot set file {file_name}'
        ]

        if tag_name:
            cmd.append(
                '{}{{tag_name}}{}'.format(
                    ' match tag ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_boot_set_file(
            self, file_name, tag_name=''):
        """
        Removes bootp options.

        This function runs the following vtysh command:

        ::

            # no boot set file {file_name}

        :param file_name: DHCP boot file name
        :param tag_name: DHCP match tag name. Length must be less than 15
            chars.
        """

        cmd = [
            'no boot set file {file_name}'
        ]

        if tag_name:
            cmd.append(
                '{}{{tag_name}}{}'.format(
                    ' match tag ', ''
                )
            )

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


class ConfigMirrorSession(ContextManager):
    """
    Mirror session configuration.

    pre_commands:

    ::

            ['config terminal', 'mirror session {name}']

    post_commands:

    ::

            ['end']
    """
    def __init__(self, enode, name):
        self.enode = enode
        self.name = name

    def __enter__(self):
        commands = """\
            config terminal
            mirror session {name}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def destination_interface(
            self, interface):
        """
        Set the destination interface.

        This function runs the following vtysh command:

        ::

            # destination interface

        :param interface: Ethernet interface or LAG
        """

        cmd = [
            'destination interface'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_destination_interface(
            self):
        """
        Un-set the destination interface and shutdown the session.

        This function runs the following vtysh command:

        ::

            # no destination interface

        """

        cmd = [
            'no destination interface'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
            self):
        """
        Shutdown the mirroring session.

        This function runs the following vtysh command:

        ::

            # shutdown

        """

        cmd = [
            'shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
            self):
        """
        Activate the mirroring session.

        This function runs the following vtysh command:

        ::

            # no shutdown

        """

        cmd = [
            'no shutdown'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def source_interface(
            self, interface, direction):
        """
        Assign a source interface.

        This function runs the following vtysh command:

        ::

            # source interface

        :param interface: Ethernet interface or LAG
        :param direction: <both | rx | tx>
        """

        cmd = [
            'source interface'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)

    def no_source_interface(
            self, interface):
        """
        Remove a source interface from the session.

        This function runs the following vtysh command:

        ::

            # no source interface

        :param interface: Ethernet interface or LAG
        """

        cmd = [
            'no source interface'
        ]

        result = self.enode(
            (' '.join(cmd)).format(**locals()),
            shell='vtysh'
        )

        if result:
            raise determine_exception(result)(result)


def show_interface(
        enode, portlbl):
    """
    Interface infomation.

    This function runs the following vtysh command:

    ::

        # show interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface`
    """

    cmd = [
        'show interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_interface(result)


def show_interface_subinterface(
        enode, portlbl):
    """
    Show subinterfaces configured on this interface

    This function runs the following vtysh command:

    ::

        # show interface {port} subinterface

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_subinterface`
    """

    cmd = [
        'show interface {port} subinterface'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_interface_subinterface(result)


def show_vlan(
        enode, vlanid=''):
    """
    Show VLAN configuration.

    This function runs the following vtysh command:

    ::

        # show vlan

    :param vlanid: Vlan ID number.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlan`
    """

    cmd = [
        'show vlan'
    ]

    if vlanid:
        cmd.append(
            '{}{{vlanid}}{}'.format(
                '', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlan(result)


def show_lacp_interface(
        enode, portlbl):
    """
    Show LACP interface.

    This function runs the following vtysh command:

    ::

        # show lacp interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_interface`
    """

    cmd = [
        'show lacp interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_lacp_interface(result)


def show_lacp_aggregates(
        enode, lag=''):
    """
    Show LACP aggregates.

    This function runs the following vtysh command:

    ::

        # show lacp aggregates

    :param lag: Link-aggregate name.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_aggregates`
    """

    cmd = [
        'show lacp aggregates'
    ]

    if lag:
        cmd.append(
            '{}{{lag}}{}'.format(
                '', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_lacp_aggregates(result)


def show_lacp_configuration(
        enode):
    """
    Show LACP configuration.

    This function runs the following vtysh command:

    ::

        # show lacp configuration

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_configuration`
    """

    cmd = [
        'show lacp configuration'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_lacp_configuration(result)


def show_lldp_neighbor_info(
        enode, portlbl):
    """
    Show global LLDP neighbor information.

    This function runs the following vtysh command:

    ::

        # show lldp neighbor-info {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lldp_neighbor_info`
    """

    cmd = [
        'show lldp neighbor-info {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_lldp_neighbor_info(result)


def show_lldp_statistics(
        enode):
    """
    Show LLDP statistics.

    This function runs the following vtysh command:

    ::

        # show lldp statistics

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lldp_statistics`
    """

    cmd = [
        'show lldp statistics'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_lldp_statistics(result)


def show_sftp_server(
        enode):
    """
    Show sftp server configuration.

    This function runs the following vtysh command:

    ::

        # show sftp server

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_sftp_server`
    """

    cmd = [
        'show sftp server'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_sftp_server(result)


def show_ip_bgp_summary(
        enode):
    """
    Show bgp neighbors information summary.

    This function runs the following vtysh command:

    ::

        # show ip bgp summary

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_summary`
    """

    cmd = [
        'show ip bgp summary'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_bgp_summary(result)


def show_ip_bgp_neighbors(
        enode):
    """
    Show bgp neighbors information.

    This function runs the following vtysh command:

    ::

        # show ip bgp neighbors

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_neighbors`
    """

    cmd = [
        'show ip bgp neighbors'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_bgp_neighbors(result)


def show_ip_bgp(
        enode):
    """
    Show bgp routing information.

    This function runs the following vtysh command:

    ::

        # show ip bgp

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp`
    """

    cmd = [
        'show ip bgp'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_bgp(result)


def show_ipv6_bgp(
        enode):
    """
    Show bgp routing information.

    This function runs the following vtysh command:

    ::

        # show ipv6 bgp

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_bgp`
    """

    cmd = [
        'show ipv6 bgp'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ipv6_bgp(result)


def show_ip_ospf_neighbor_detail(
        enode):
    """
    Show ospf neighbor detail information.

    This function runs the following vtysh command:

    ::

        # show ip ospf neighbor detail

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_neighbor_detail`
    """

    cmd = [
        'show ip ospf neighbor detail'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_ospf_neighbor_detail(result)


def show_ip_ospf_neighbor(
        enode):
    """
    Show ospf neighbor information.

    This function runs the following vtysh command:

    ::

        # show ip ospf neighbor

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_neighbor`
    """

    cmd = [
        'show ip ospf neighbor'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_ospf_neighbor(result)


def show_ip_ospf_interface(
        enode):
    """
    Show ospf interface detail.

    This function runs the following vtysh command:

    ::

        # show ip ospf interface

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_interface`
    """

    cmd = [
        'show ip ospf interface'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_ospf_interface(result)


def show_ip_ospf(
        enode):
    """
    Show ospf detail.

    This function runs the following vtysh command:

    ::

        # show ip ospf

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf`
    """

    cmd = [
        'show ip ospf'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_ospf(result)


def show_running_config(
        enode):
    """
    Show running-config information.

    This function runs the following vtysh command:

    ::

        # show running-config

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_running_config`
    """

    cmd = [
        'show running-config'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_running_config(result)


def show_ip_route(
        enode):
    """
    Show Routing Table.

    This function runs the following vtysh command:

    ::

        # show ip route

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_route`
    """

    cmd = [
        'show ip route'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_route(result)


def show_ipv6_route(
        enode):
    """
    Display the routing table.

    This function runs the following vtysh command:

    ::

        # show ipv6 route

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_route`
    """

    cmd = [
        'show ipv6 route'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ipv6_route(result)


def show_sflow(
        enode):
    """
    Show sFlow information.

    This function runs the following vtysh command:

    ::

        # show sflow

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_sflow`
    """

    cmd = [
        'show sflow'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_sflow(result)


def show_sflow_interface(
        enode, portlbl):
    """
    Show sFlow information for the interface.

    This function runs the following vtysh command:

    ::

        # show sflow interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_sflow_interface`
    """

    cmd = [
        'show sflow interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_sflow_interface(result)


def show_udld_interface(
        enode, portlbl):
    """
    Show UDLD information for the interface.

    This function runs the following vtysh command:

    ::

        # show udld interface {port}

    :param portlbl: Label that identifies interface.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_udld_interface`
    """

    cmd = [
        'show udld interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_udld_interface(result)


def show_rib(
        enode):
    """
    Show Routing Information Base.

    This function runs the following vtysh command:

    ::

        # show rib

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_rib`
    """

    cmd = [
        'show rib'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_rib(result)


def show_ip_ecmp(
        enode):
    """
    Show ECMP Configuration

    This function runs the following vtysh command:

    ::

        # show ip ecmp

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ecmp`
    """

    cmd = [
        'show ip ecmp'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ip_ecmp(result)


def clear_udld_statistics(
        enode):
    """
    Clear UDLD statistics from all interfaces.

    This function runs the following vtysh command:

    ::

        # clear udld statistics

    """

    cmd = [
        'clear udld statistics'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    if result:
        raise determine_exception(result)(result)


def clear_udld_statistics_interface(
        enode, portlbl):
    """
    Clear UDLD statistics for the interface.

    This function runs the following vtysh command:

    ::

        # clear udld statistics interface {port}

    :param portlbl: Label that identifies interface.
    """

    cmd = [
        'clear udld statistics interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    if result:
        raise determine_exception(result)(result)


def ping_repetitions(
        enode, destination, count):
    """
    Send IPv4 ping

    This function runs the following vtysh command:

    ::

        # ping {destination} repetitions {count}

    :param destination: <A.B.C.D> IPv4 address.
    :param count: Number of packets to send.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping_repetitions`
    """

    cmd = [
        'ping {destination} repetitions {count}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_ping_repetitions(result)


def ping6_repetitions(
        enode, destination, count):
    """
    Send IPv6 ping

    This function runs the following vtysh command:

    ::

        # ping6 {destination} repetitions {count}

    :param destination: <X:X::X:X> IPv6 address.
    :param count: Number of packets to send.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping6_repetitions`
    """

    cmd = [
        'ping6 {destination} repetitions {count}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_ping6_repetitions(result)


def ping(
        enode, destination, count='', size='', data='', interval='',
        timeout='', tos='', ip_option=''):
    """
    Send IPv4 ping

    This function runs the following vtysh command:

    ::

        # ping {destination}

    :param destination: <A.B.C.D> IPv4 address.
    :param count: Number of packets to send.
    :param size: Size of packets to send.
    :param data: Data to be filled in each packet.
    :param interval: Time interval between ping requests.
    :param timeout: Max time to wait for ping reply.
    :param tos: Type of service to be placed in each probe.
    :param ip_option: Ip-option.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping`
    """

    cmd = [
        'ping {destination}'
    ]

    if count:
        cmd.append(
            '{}{{count}}{}'.format(
                'repetitions ', ''
            )
        )

    if size:
        cmd.append(
            '{}{{size}}{}'.format(
                'datagram-size ', ''
            )
        )

    if data:
        cmd.append(
            '{}{{data}}{}'.format(
                'data-fill ', ''
            )
        )

    if interval:
        cmd.append(
            '{}{{interval}}{}'.format(
                'interval ', ''
            )
        )

    if timeout:
        cmd.append(
            '{}{{timeout}}{}'.format(
                'timeout ', ''
            )
        )

    if tos:
        cmd.append(
            '{}{{tos}}{}'.format(
                'tos ', ''
            )
        )

    if ip_option:
        cmd.append(
            '{}{{ip_option}}{}'.format(
                'ip-option ', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_ping(result)


def ping6(
        enode, destination, count='', size='', data='', interval=''):
    """
    Send IPv6 ping

    This function runs the following vtysh command:

    ::

        # ping6 {destination}

    :param destination: <X:X::X:X> IPv6 address.
    :param count: Number of packets to send.
    :param size: Size of packets to send.
    :param data: Data to be filled in each packet.
    :param interval: Time interval between ping requests.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping6`
    """

    cmd = [
        'ping6 {destination}'
    ]

    if count:
        cmd.append(
            '{}{{count}}{}'.format(
                'repetitions ', ''
            )
        )

    if size:
        cmd.append(
            '{}{{size}}{}'.format(
                'datagram-size ', ''
            )
        )

    if data:
        cmd.append(
            '{}{{data}}{}'.format(
                'data-fill ', ''
            )
        )

    if interval:
        cmd.append(
            '{}{{interval}}{}'.format(
                'interval ', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_ping6(result)


def traceroute(
        enode, destination, min_ttl='', max_ttl='', dst_port='',
        time_out='', probes='', ip_option_source=''):
    """
    Send IPv4 traceroute

    This function runs the following vtysh command:

    ::

        # traceroute {destination}

    :param destination: <A.B.C.D> IPv4 address.
    :param min_ttl: Minimum number of hops to reach the destination <1-255>.
    :param max_ttl: Maximum number of hops to reach the destination <1-255>.
    :param dst_port: Destination port <1-34000>.
    :param time_out: Traceroute timeout in seconds <1-60>.
    :param probes: Number of Probes <1-5>.
    :param ip_option_source: Source for loose source route record.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_traceroute`
    """

    cmd = [
        'traceroute {destination}'
    ]

    if min_ttl:
        cmd.append(
            '{}{{min_ttl}}{}'.format(
                'minttl ', ''
            )
        )

    if max_ttl:
        cmd.append(
            '{}{{max_ttl}}{}'.format(
                'maxttl ', ''
            )
        )

    if dst_port:
        cmd.append(
            '{}{{dst_port}}{}'.format(
                'dstport ', ''
            )
        )

    if time_out:
        cmd.append(
            '{}{{time_out}}{}'.format(
                'timeout ', ''
            )
        )

    if probes:
        cmd.append(
            '{}{{probes}}{}'.format(
                'probes ', ''
            )
        )

    if ip_option_source:
        cmd.append(
            '{}{{ip_option_source}}{}'.format(
                'ip-option loosesourceroute ', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_traceroute(result)


def traceroute6(
        enode, destination, max_ttl='', dst_port='', time_out='',
        probes=''):
    """
    Send IPv6 traceroute

    This function runs the following vtysh command:

    ::

        # traceroute6 {destination}

    :param destination: <X:X::X:X> IPv6 address.
    :param max_ttl: Maximum number of hops to reach the destination <1-255>.
    :param dst_port: Destination port <1-34000>.
    :param time_out: Traceroute timeout in seconds <1-60>.
    :param probes: Number of Probes <1-5>.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_traceroute6`
    """

    cmd = [
        'traceroute6 {destination}'
    ]

    if max_ttl:
        cmd.append(
            '{}{{max_ttl}}{}'.format(
                'maxttl ', ''
            )
        )

    if dst_port:
        cmd.append(
            '{}{{dst_port}}{}'.format(
                'dstport ', ''
            )
        )

    if time_out:
        cmd.append(
            '{}{{time_out}}{}'.format(
                'timeout ', ''
            )
        )

    if probes:
        cmd.append(
            '{}{{probes}}{}'.format(
                'probes ', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_traceroute6(result)


def show_ntp_associations(
        enode):
    """
    Show NTP Association summary.

    This function runs the following vtysh command:

    ::

        # show ntp associations

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_associations`
    """

    cmd = [
        'show ntp associations'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ntp_associations(result)


def show_ntp_authentication_key(
        enode):
    """
    Show NTP Authentication Keys information.

    This function runs the following vtysh command:

    ::

        # show ntp authentication-key

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_authentication_key`
    """

    cmd = [
        'show ntp authentication-key'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ntp_authentication_key(result)


def show_ntp_statistics(
        enode):
    """
    Show NTP Statistics information.

    This function runs the following vtysh command:

    ::

        # show ntp statistics

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_statistics`
    """

    cmd = [
        'show ntp statistics'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ntp_statistics(result)


def show_ntp_status(
        enode):
    """
    Show NTP Status information.

    This function runs the following vtysh command:

    ::

        # show ntp status

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_status`
    """

    cmd = [
        'show ntp status'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ntp_status(result)


def show_ntp_trusted_keys(
        enode):
    """
    Show NTP Trusted Keys information.

    This function runs the following vtysh command:

    ::

        # show ntp trusted-keys

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_trusted_keys`
    """

    cmd = [
        'show ntp trusted-keys'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_ntp_trusted_keys(result)


def show_dhcp_server_leases(
        enode):
    """
    Show DHCP server leases information.

    This function runs the following vtysh command:

    ::

        # show dhcp-server leases

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_dhcp_server_leases`
    """

    cmd = [
        'show dhcp-server leases'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_dhcp_server_leases(result)


def show_dhcp_server(
        enode):
    """
    Display DHCP server configuration.

    This function runs the following vtysh command:

    ::

        # show dhcp-server

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_dhcp_server`
    """

    cmd = [
        'show dhcp-server'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_dhcp_server(result)


def show_mac_address_table(
        enode):
    """
    Display L2 MAC address table information.

    This function runs the following vtysh command:

    ::

        # show mac-address-table

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_mac_address_table`
    """

    cmd = [
        'show mac-address-table'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_mac_address_table(result)


def show_vlog_config(
        enode):
    """
    Display vlog config.

    This function runs the following vtysh command:

    ::

        # show vlog config

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config`
    """

    cmd = [
        'show vlog config'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_config(result)


def show_vlog(
        enode, sub_command):
    """
    Show vlog sub command.

    This function runs the following vtysh command:

    ::

        # show vlog {sub_command}

    :param sub_command: sub command
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog`
    """

    cmd = [
        'show vlog {sub_command}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog(result)


def show_interface_loopback(
        enode, loopback_int=''):
    """
    Show loopback interfaces on ops

    This function runs the following vtysh command:

    ::

        # show interface loopback

    :param loopback_int: Loopback interface id.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_loopback`
    """

    cmd = [
        'show interface loopback'
    ]

    if loopback_int:
        cmd.append(
            '{}{{loopback_int}}{}'.format(
                '', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_interface_loopback(result)


def show_interface_loopback_brief(
        enode):
    """
    Display information for L3 loopback interfaces

    This function runs the following vtysh command:

    ::

        # show interface loopback brief

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_loopback_brief`
    """

    cmd = [
        'show interface loopback brief'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_interface_loopback_brief(result)


def show_vlog_config_daemon(
        enode, daemon_name):
    """
    Display vlog config for ops-daemons.

    This function runs the following vtysh command:

    ::

        # show vlog config daemon {daemon_name}

    :param daemon_name: daemon name
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config_daemon`
    """

    cmd = [
        'show vlog config daemon {daemon_name}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_config_daemon(result)


def show_vlog_config_feature(
        enode, feature_name):
    """
    Display vlog config for feature

    This function runs the following vtysh command:

    ::

        # show vlog config feature {feature_name}

    :param feature_name: feature name
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config_feature`
    """

    cmd = [
        'show vlog config feature {feature_name}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_config_feature(result)


def show_vlog_config_list(
        enode):
    """
    Display vlog config for supported features list

    This function runs the following vtysh command:

    ::

        # show vlog config list

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config_list`
    """

    cmd = [
        'show vlog config list'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_config_list(result)


def show_vlog_daemon(
        enode, daemon_name):
    """
    Display vlogs for ops-daemon

    This function runs the following vtysh command:

    ::

        # show vlog daemon {daemon_name}

    :param daemon_name: daemon name
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_daemon`
    """

    cmd = [
        'show vlog daemon {daemon_name}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_daemon(result)


def show_vlog_severity(
        enode, severity_level):
    """
    Display vlogs for severity level

    This function runs the following vtysh command:

    ::

        # show vlog severity {severity_level}

    :param severity_level: severity level
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_severity`
    """

    cmd = [
        'show vlog severity {severity_level}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_severity(result)


def show_vlog_daemon_severity(
        enode, daemonname, severity):
    """
    Display vlogs for ops-daemon with severity

    This function runs the following vtysh command:

    ::

        # show vlog daemon {daemonname} severity {severity}

    :param daemonname: daemon name
    :param severity: severity level
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_daemon_severity`
    """

    cmd = [
        'show vlog daemon {daemonname} severity {severity}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_daemon_severity(result)


def show_vlog_severity_daemon(
        enode, severity, daemonname):
    """
    Display vlogs for severity with ops-daemon

    This function runs the following vtysh command:

    ::

        # show vlog severity {severity} daemon {daemonname}

    :param severity: severity level
    :param daemonname: daemon name
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_severity_daemon`
    """

    cmd = [
        'show vlog severity {severity} daemon {daemonname}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_vlog_severity_daemon(result)


def copy_running_config_startup_config(
        enode):
    """
    copies running config to startup config

    This function runs the following vtysh command:

    ::

        # copy running-config startup-config

    """

    cmd = [
        'copy running-config startup-config'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    if result:
        raise determine_exception(result)(result)


def show_startup_config(
        enode):
    """
    Show startup-config information.

    This function runs the following vtysh command:

    ::

        # show startup-config

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_startup_config`
    """

    cmd = [
        'show startup-config'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_startup_config(result)


def show_tftp_server(
        enode):
    """
    Display TFTP-Server configuration.

    This function runs the following vtysh command:

    ::

        # show tftp-server

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_tftp_server`
    """

    cmd = [
        'show tftp-server'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_tftp_server(result)


def no_mirror_session(
        enode, name):
    """
    Delete a mirroring session.

    This function runs the following vtysh command:

    ::

        # no mirror session {name}

    :param name: Up to 64 letters, numbers, underscores, dashes, or periods.
    """

    cmd = [
        'no mirror session {name}'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    if result:
        raise determine_exception(result)(result)


def show_mirror(
        enode, name=''):
    """
    Show mirroring session information.

    This function runs the following vtysh command:

    ::

        # show mirror {name}

    :param name: Up to 64 letters, numbers, underscores, dashes, or periods.
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_mirror`
    """

    cmd = [
        'show mirror {name}'
    ]

    if name:
        cmd.append(
            '{}{{name}}{}'.format(
                '', ''
            )
        )

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_mirror(result)


def show_snmp_community(
        enode):
    """
    Display SNMP configured community names.

    This function runs the following vtysh command:

    ::

        # show snmp community

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_community`
    """

    cmd = [
        'show snmp community'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_snmp_community(result)


def show_snmp_system(
        enode):
    """
    Display SNMP system information.

    This function runs the following vtysh command:

    ::

        # show snmp system

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_system`
    """

    cmd = [
        'show snmp system'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_snmp_system(result)


def show_snmp_trap(
        enode):
    """
    Display SNMP host information of trap receivers.

    This function runs the following vtysh command:

    ::

        # show snmp trap

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_trap`
    """

    cmd = [
        'show snmp trap'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_snmp_trap(result)


def diag_dump_lacp_basic(
        enode):
    """
    Displays diagnostic information for LACP

    This function runs the following vtysh command:

    ::

        # diag-dump lacp basic

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_diag_dump_lacp_basic`
    """

    cmd = [
        'diag-dump lacp basic'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_diag_dump_lacp_basic(result)


def show_snmpv3_users(
        enode):
    """
    Display SNMPV3 users.

    This function runs the following vtysh command:

    ::

        # show snmpv3 users

    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmpv3_users`
    """

    cmd = [
        'show snmpv3 users'
    ]

    result = enode(
        (' '.join(cmd)).format(**locals()),
        shell='vtysh'
    )

    return parse_show_snmpv3_users(result)


__all__ = [
    'ContextManager',
    'Configure',
    'RouteMap',
    'ConfigInterface',
    'ConfigSubinterface',
    'ConfigInterfaceVlan',
    'ConfigInterfaceLoopback',
    'ConfigInterfaceLag',
    'ConfigInterfaceMgmt',
    'ConfigRouterOspf',
    'ConfigRouterBgp',
    'ConfigVlan',
    'ConfigTftpServer',
    'ConfigDhcpServer',
    'ConfigMirrorSession',
    'show_interface',
    'show_interface_subinterface',
    'show_vlan',
    'show_lacp_interface',
    'show_lacp_aggregates',
    'show_lacp_configuration',
    'show_lldp_neighbor_info',
    'show_lldp_statistics',
    'show_sftp_server',
    'show_ip_bgp_summary',
    'show_ip_bgp_neighbors',
    'show_ip_bgp',
    'show_ipv6_bgp',
    'show_ip_ospf_neighbor_detail',
    'show_ip_ospf_neighbor',
    'show_ip_ospf_interface',
    'show_ip_ospf',
    'show_running_config',
    'show_ip_route',
    'show_ipv6_route',
    'show_sflow',
    'show_sflow_interface',
    'show_udld_interface',
    'show_rib',
    'show_ip_ecmp',
    'clear_udld_statistics',
    'clear_udld_statistics_interface',
    'ping_repetitions',
    'ping6_repetitions',
    'ping',
    'ping6',
    'traceroute',
    'traceroute6',
    'show_ntp_associations',
    'show_ntp_authentication_key',
    'show_ntp_statistics',
    'show_ntp_status',
    'show_ntp_trusted_keys',
    'show_dhcp_server_leases',
    'show_dhcp_server',
    'show_mac_address_table',
    'show_vlog_config',
    'show_vlog',
    'show_interface_loopback',
    'show_interface_loopback_brief',
    'show_vlog_config_daemon',
    'show_vlog_config_feature',
    'show_vlog_config_list',
    'show_vlog_daemon',
    'show_vlog_severity',
    'show_vlog_daemon_severity',
    'show_vlog_severity_daemon',
    'copy_running_config_startup_config',
    'show_startup_config',
    'show_tftp_server',
    'no_mirror_session',
    'show_mirror',
    'show_snmp_community',
    'show_snmp_system',
    'show_snmp_trap',
    'diag_dump_lacp_basic',
    'show_snmpv3_users'
]
