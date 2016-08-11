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
    """  # noqa
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

    def hostname(
        self, hostname,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure hostname

        This function runs the following vtysh command:

        ::

            # hostname {hostname}

        :param hostname: Hostname string(Max Length 32), first letter must be
            alphabet
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'hostname {hostname}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_hostname(
        self, hostname='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete  name of the host

        This function runs the following vtysh command:

        ::

            # no hostname

        :param hostname: Hostname string(Max Length 32), first letter must be
            alphabet
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no hostname'
        ]

        if hostname:
            cmd.append(
                '{}{{hostname}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete a VLAN

        This function runs the following vtysh command:

        ::

            # no vlan {vlan_id}

        :param vlan_id: VLAN Identifier.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_internal_range(
        self, min_range, max_range, order,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set internal vlan range configuration <2-4094

        This function runs the following vtysh command:

        ::

            # vlan internal range {min_range} {max_range} {order}

        :param min_range: minimum vlan range for internal vlan is 2
        :param max_range: maximum vlan range for internal vlan is 4094
        :param order: Assign vlan in ascending(default) or
            descending order
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan internal range {min_range} {max_range} {order}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_interface_lag(
        self, lag_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete a lag

        This function runs the following vtysh command:

        ::

            # no interface lag {lag_id}

        :param lag_id: link-aggregation identifier.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no interface lag {lag_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_interface_vlan(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete a interface vlan

        This function runs the following vtysh command:

        ::

            # no interface vlan {vlan_id}

        :param vlan_id: VLAN Interface Identifier.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no interface vlan {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vrf(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure vrf

        This function runs the following vtysh command:

        ::

            # vrf {vrf_name}

        :param vrf_name: VRF NAME
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vrf {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vrf(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete  vrf

        This function runs the following vtysh command:

        ::

            # no vrf {vrf_name}

        :param vrf_name: VRF NAME
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vrf {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_interface_loopback(
        self, loopback_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete a L3 loopback interface

        This function runs the following vtysh command:

        ::

            # no interface loopback {loopback_id}

        :param loopback_id: Loopback interface identifier.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no interface loopback {loopback_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def session_timeout(
        self, mins,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Idle timeout range in minutes,0 disables the timeout

        This function runs the following vtysh command:

        ::

            # session-timeout {mins}

        :param mins: timeout in minutes
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'session-timeout {mins}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_interface(
        self, portlbl, subint,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete a subinterface

        This function runs the following vtysh command:

        ::

            # no interface {port}.{subint}

        :param portlbl: Physical interface associated to subinterface
        :param subint: Subinterface ID
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no interface {port}.{subint}'
        ]

        port = self.enode.ports.get(portlbl, portlbl)

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_route(
        self, ipv4, next_hop, metric='', vrf_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure static routes

        This function runs the following vtysh command:

        ::

            # ip route {ipv4} {next_hop}

        :param ipv4: A.B.C.D/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        :param vrf_name: VRF based route address to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        if vrf_name:
            cmd.append(
                '{}{{vrf_name}}{}'.format(
                    'vrf ', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_route(
        self, ipv4, next_hop, metric='', vrf_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-configure static routes

        This function runs the following vtysh command:

        ::

            # no ip route {ipv4} {next_hop}

        :param ipv4: A.B.C.D/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        :param vrf_name: VRF based route address to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        if vrf_name:
            cmd.append(
                '{}{{vrf_name}}{}'.format(
                    'vrf ', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_prefix_list_seq(
        self, prefix_name, seq, permission, network,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip prefix-list {prefix_name} seq {seq} {permission} {network}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_prefix_list_seq(
        self, prefix_name, seq, permission, network,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip prefix-list {prefix_name} seq {seq} {permission} {network}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_prefix_list_seq(
        self, prefix_name, seq, permission, network,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_prefix_list_seq(
        self, prefix_name, seq, permission, network,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Deletes the IPv6 prefix-list

        This function runs the following vtysh command:

        ::

            # no ipv6 prefix-list {prefix_name} seq {seq} {permission} {network} # noqa

        :param prefix_name: WORD  The IP prefix-list name
        :param seq: <1-4294967295>  Sequence number
        :param permission: deny    Specify packets to rejectpermit  Specify
            packets to forward
        :param network: X:X::X:X/M IPv6 prefix
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 prefix-list {prefix_name} seq {seq} {permission} {network}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_route_map(
        self, routemap_name, permission, seq,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no route-map {routemap_name} {permission} {seq}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_route(
        self, ipv6, next_hop, metric='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure static routes

        This function runs the following vtysh command:

        ::

            # ipv6 route {ipv6} {next_hop}

        :param ipv6: X:X::X:X/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_route(
        self, ipv6, next_hop, metric='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-configure static routes

        This function runs the following vtysh command:

        ::

            # no ipv6 route {ipv6} {next_hop}

        :param ipv6: X:X::X:X/M IP destination prefix.
        :param next_hop: Can be an ip address or a interface.
        :param metric: Optional, route address to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_qos_queue_profile_schedule_profile(
        self, queue_profile_name, schedule_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Applies qos profiles.

        This function runs the following vtysh command:

        ::

            # apply qos queue-profile {queue_profile_name} schedule-profile {schedule_profile_name} # noqa

        :param queue_profile_name: The queue profile to apply.
        :param schedule_profile_name: The schedule profile to apply.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'apply qos queue-profile {queue_profile_name} schedule-profile {schedule_profile_name}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_cos_map_local_priority(
        self, code_point, local_priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos cos-map.

        This function runs the following vtysh command:

        ::

            # qos cos-map {code_point} local-priority {local_priority}

        :param code_point: The code point of the cos map entry.
        :param local_priority: The local priority of the cos map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos cos-map {code_point} local-priority {local_priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_cos_map_local_priority_color(
        self, code_point, local_priority, color,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos cos-map.

        This function runs the following vtysh command:

        ::

            # qos cos-map {code_point} local-priority {local_priority} color {color} # noqa

        :param code_point: The code point of the cos map entry.
        :param local_priority: The local priority of the cos map entry.
        :param color: The color of the cos map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos cos-map {code_point} local-priority {local_priority} color {color}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_cos_map_local_priority_name(
        self, code_point, local_priority, name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos cos-map.

        This function runs the following vtysh command:

        ::

            # qos cos-map {code_point} local-priority {local_priority} name {name} # noqa

        :param code_point: The code point of the cos map entry.
        :param local_priority: The local priority of the cos map entry.
        :param name: The name of the cos map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos cos-map {code_point} local-priority {local_priority} name {name}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_cos_map_local_priority_color_name(
        self, code_point, local_priority, color, name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos cos-map.

        This function runs the following vtysh command:

        ::

            # qos cos-map {code_point} local-priority {local_priority} color {color} name {name} # noqa

        :param code_point: The code point of the cos map entry.
        :param local_priority: The local priority of the cos map entry.
        :param color: The color of the cos map entry.
        :param name: The name of the cos map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos cos-map {code_point} local-priority {local_priority} color {color} name {name}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_cos_map_local_priority_name_color(
        self, code_point, local_priority, name, color,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos cos-map.

        This function runs the following vtysh command:

        ::

            # qos cos-map {code_point} local-priority {local_priority} name {name} color {color} # noqa

        :param code_point: The code point of the cos map entry.
        :param local_priority: The local priority of the cos map entry.
        :param name: The name of the cos map entry.
        :param color: The color of the cos map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos cos-map {code_point} local-priority {local_priority} name {name} color {color}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_cos_map(
        self, code_point,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Restores a qos cos-map entry to factory default.

        This function runs the following vtysh command:

        ::

            # no qos cos-map {code_point}

        :param code_point: The code point of the cos map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos cos-map {code_point}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp_map_local_priority(
        self, code_point, local_priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos dscp-map.

        This function runs the following vtysh command:

        ::

            # qos dscp-map {code_point} local-priority {local_priority}

        :param code_point: The code point of the dscp map entry.
        :param local_priority: The local priority of the dscp map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos dscp-map {code_point} local-priority {local_priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp_map_local_priority_color(
        self, code_point, local_priority, color,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos dscp-map.

        This function runs the following vtysh command:

        ::

            # qos dscp-map {code_point} local-priority {local_priority} color {color} # noqa

        :param code_point: The code point of the dscp map entry.
        :param local_priority: The local priority of the dscp map entry.
        :param color: The color of the dscp map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos dscp-map {code_point} local-priority {local_priority} color {color}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp_map_local_priority_name(
        self, code_point, local_priority, name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos dscp-map.

        This function runs the following vtysh command:

        ::

            # qos dscp-map {code_point} local-priority {local_priority} name {name} # noqa

        :param code_point: The code point of the dscp map entry.
        :param local_priority: The local priority of the dscp map entry.
        :param name: The name of the dscp map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos dscp-map {code_point} local-priority {local_priority} name {name}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp_map_local_priority_color_name(
        self, code_point, local_priority, color, name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos dscp-map.

        This function runs the following vtysh command:

        ::

            # qos dscp-map {code_point} local-priority {local_priority} color {color} name {name} # noqa

        :param code_point: The code point of the dscp map entry.
        :param local_priority: The local priority of the dscp map entry.
        :param color: The color of the dscp map entry.
        :param name: The name of the dscp map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos dscp-map {code_point} local-priority {local_priority} color {color} name {name}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp_map_local_priority_name_color(
        self, code_point, local_priority, name, color,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the qos dscp-map.

        This function runs the following vtysh command:

        ::

            # qos dscp-map {code_point} local-priority {local_priority} name {name} color {color} # noqa

        :param code_point: The code point of the dscp map entry.
        :param local_priority: The local priority of the dscp map entry.
        :param name: The name of the dscp map entry.
        :param color: The color of the dscp map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'qos dscp-map {code_point} local-priority {local_priority} name {name} color {color}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_dscp_map(
        self, code_point,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Restores a qos dscp-map entry to factory default.

        This function runs the following vtysh command:

        ::

            # no qos dscp-map {code_point}

        :param code_point: The code point of the dscp map entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos dscp-map {code_point}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_queue_profile(
        self, queue_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Creates a queue profile.

        This function runs the following vtysh command:

        ::

            # qos queue-profile {queue_profile_name}

        :param queue_profile_name: Up to 64 letters, numbers, underscores,
            dashes, or periods.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos queue-profile {queue_profile_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_queue_profile(
        self, queue_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Deletes a queue profile.

        This function runs the following vtysh command:

        ::

            # no qos queue-profile {queue_profile_name}

        :param queue_profile_name: Up to 64 letters, numbers, underscores,
            dashes, or periods.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos queue-profile {queue_profile_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_schedule_profile(
        self, schedule_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Creates a schedule profile.

        This function runs the following vtysh command:

        ::

            # qos schedule-profile {schedule_profile_name}

        :param schedule_profile_name: Up to 64 letters, numbers, underscores,
            dashes, or periods.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos schedule-profile {schedule_profile_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_schedule_profile(
        self, schedule_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Deletes a schedule profile.

        This function runs the following vtysh command:

        ::

            # no qos schedule-profile {schedule_profile_name}

        :param schedule_profile_name: Up to 64 letters, numbers, underscores,
            dashes, or periods.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos schedule-profile {schedule_profile_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_trust(
        self, value,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets qos trust.

        This function runs the following vtysh command:

        ::

            # qos trust {value}

        :param value: none, cos, or dscp
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos trust {value}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_trust(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Restores qos trust to its factory default.

        This function runs the following vtysh command:

        ::

            # no qos trust

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos trust'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_system_priority(
        self, priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set LACP system priority.

        This function runs the following vtysh command:

        ::

            # lacp system-priority {priority}

        :param priority: <0-65535>  The range is 0 to 65535.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp system-priority {priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable LLDP globally.

        This function runs the following vtysh command:

        ::

            # lldp enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable LLDP globally.

        This function runs the following vtysh command:

        ::

            # no lldp enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_clear(
        self, param,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clear LLDP counters and neighbors.

        This function runs the following vtysh command:

        ::

            # lldp clear {param}

        :param param: counters clear lldp countersneighbors clear lldp
            neighbors
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp clear {param}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_holdtime(
        self, holdtime_multiplier,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure hold time multiplier.

        This function runs the following vtysh command:

        ::

            # lldp holdtime {holdtime_multiplier}

        :param holdtime_multiplier: <5-32768>  holdtime_multiplier range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp holdtime {holdtime_multiplier}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_holdtime(
        self, holdtime_multiplier,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure hold time multiplier.

        This function runs the following vtysh command:

        ::

            # no lldp holdtime {holdtime_multiplier}

        :param holdtime_multiplier: <5-32768>  holdtime_multiplier range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp holdtime {holdtime_multiplier}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_management_address(
        self, lldp_mgmt_address,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure LLDP management IPV4/IPV6 address.

        This function runs the following vtysh command:

        ::

            # lldp management-address {lldp_mgmt_address}

        :param lldp_mgmt_address: A.B.C.D/X:X::X:X IPV4/IPV6 address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp management-address {lldp_mgmt_address}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_management_address(
        self, lldp_mgmt_address,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure LLDP management IPV4/IPV6 address.

        This function runs the following vtysh command:

        ::

            # no lldp management-address {lldp_mgmt_address}

        :param lldp_mgmt_address: A.B.C.D/X:X::X:X IPV4/IPV6 address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp management-address {lldp_mgmt_address}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_reinit(
        self, reinit_timer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure wait time before LLDP initialization.

        This function runs the following vtysh command:

        ::

            # lldp reinit {reinit_timer}

        :param reinit_timer: <1-10>  reinit_timer range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp reinit {reinit_timer}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_reinit(
        self, reinit_timer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure wait time before LLDP initialization.

        This function runs the following vtysh command:

        ::

            # no lldp reinit {reinit_timer}

        :param reinit_timer: <1-10>  reinit_timer range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp reinit {reinit_timer}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_select_tlv(
        self, tlv_field,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enabling LLDP tlv field management IP address.

        This function runs the following vtysh command:

        ::

            # lldp select-tlv {tlv_field}

        :param tlv_field: management-address Enable management-addressport-
            description Enable port-descriptionport-protocol-id Enable port-
            protocol-idport-protocol-vlan-id Enable
            port-protocol-vlan-idport-vlan-id Enable port-vlan-idport-vlan-name
            Enable port-vlan-namesystem-capabilities Enable system-
            capabilitiessystem-description Enable system-descriptionsystem-name
            Enable system-name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp select-tlv {tlv_field}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_select_tlv(
        self, tlv_field,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enabling LLDP tlv field management IP address.

        This function runs the following vtysh command:

        ::

            # no lldp select-tlv {tlv_field}

        :param tlv_field: management-address Enable management-addressport-
            description Enable port-descriptionport-protocol-id Enable port-
            protocol-idport-protocol-vlan-id Enable
            port-protocol-vlan-idport-vlan-id Enable port-vlan-idport-vlan-name
            Enable port-vlan-namesystem-capabilities Enable system-
            capabilitiessystem-description Enable system-descriptionsystem-name
            Enable system-name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp select-tlv {tlv_field}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_timer(
        self, lldp_update_timer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure LLDP status update interval.

        This function runs the following vtysh command:

        ::

            # lldp timer {lldp_update_timer}

        :param lldp_update_timer: <5-32768>  lldp_update_timer range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp timer {lldp_update_timer}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_timer(
        self, lldp_update_timer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure LLDP status update interval.

        This function runs the following vtysh command:

        ::

            # no lldp timer {lldp_update_timer}

        :param lldp_update_timer: <5-32768>  lldp_update_timer range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp timer {lldp_update_timer}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure sFlow.

        This function runs the following vtysh command:

        ::

            # sflow enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-configure sFlow.

        This function runs the following vtysh command:

        ::

            # no sflow enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_sampling(
        self, rate,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow sampling rate.

        This function runs the following vtysh command:

        ::

            # sflow sampling {rate}

        :param rate: <1-1000000000>  The range is 1 to 1000000000.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow sampling {rate}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_header_size(
        self, size,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow header-size size.

        This function runs the following vtysh command:

        ::

            # sflow header-size {size}

        :param size: <64-256>  The size is 64 to 256.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow header-size {size}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_header_size(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset sFlow header-size

        This function runs the following vtysh command:

        ::

            # no sflow header-size

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow header-size'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_max_datagram_size(
        self, size,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow max-datagram-size size.

        This function runs the following vtysh command:

        ::

            # sflow max-datagram-size {size}

        :param size: <1-9000>  The size is 1 to 9000.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow max-datagram-size {size}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_max_datagram_size(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset sFlow max-datagram-size

        This function runs the following vtysh command:

        ::

            # no sflow max-datagram-size

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow max-datagram-size'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_sampling(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Reset sFlow sampling rate to default.

        This function runs the following vtysh command:

        ::

            # no sflow sampling

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow sampling'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_polling(
        self, interval,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow polling interval.

        This function runs the following vtysh command:

        ::

            # sflow polling {interval}

        :param interval: <0-3600>  The range is 0 to 3600.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow polling {interval}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_polling(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Reset sFlow polling interval to default.

        This function runs the following vtysh command:

        ::

            # no sflow polling

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow polling'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_agent_interface(
        self, portlbl, address_family='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow agent interface

        This function runs the following vtysh command:

        ::

            # sflow agent-interface {portlbl}

        :param portlbl: Valid L3 interface name.
        :param address_family: Optional, IPv4 or IPv6 (Default : IPv4).
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_agent_interface(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove sFlow agent interface configuration.

        This function runs the following vtysh command:

        ::

            # no sflow agent-interface

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow agent-interface'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow collector configuration (IP)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip}

        :param ip: IP address of collector.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow collector {ip}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_port(
        self, ip, port,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow collector configuration (IP, port)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} port {port}

        :param ip: IP address of collector.
        :param port: Port of collector <0-65535> (Default : 6343).
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow collector {ip} port {port}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_vrf(
        self, ip, vrf,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow collector configuration (IP, vrf)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} vrf {vrf}

        :param ip: IP address of collector.
        :param vrf: Name of VRF (Default : vrf_default).
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow collector {ip} vrf {vrf}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_collector_port_vrf(
        self, ip, port, vrf,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set sFlow collector configuration (IP, port, vrf)

        This function runs the following vtysh command:

        ::

            # sflow collector {ip} port {port} vrf {vrf}

        :param ip: IP address of collector.
        :param port: Port of collector <0-65535> (Default : 6343).
        :param vrf: Name of VRF (Default : vrf_default).
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow collector {ip} port {port} vrf {vrf}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_router_bgp(
        self, asn,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the BGP Router

        This function runs the following vtysh command:

        ::

            # no router bgp {asn}

        :param asn: Autonomous System Number.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no router bgp {asn}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def track_interface(
        self, track_id, interface,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Create track object for interface

        This function runs the following vtysh command:

        ::

            # track {track_id} interface {interface}

        :param track_id: [1-500] Track object ID
        :param interface: Interface name to be tracked
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'track {track_id} interface {interface}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_track(
        self, track_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove track object for interface

        This function runs the following vtysh command:

        ::

            # no track {track_id}

        :param track_id: [1-500] Track object ID
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no track {track_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_router_ospf(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the OSPF Router

        This function runs the following vtysh command:

        ::

            # no router ospf

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no router ospf'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def router_vrrp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enables the VRRP Router

        This function runs the following vtysh command:

        ::

            # router vrrp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'router vrrp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_router_vrrp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disables the VRRP Router

        This function runs the following vtysh command:

        ::

            # no router vrrp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no router vrrp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Completely disable ECMP

        This function runs the following vtysh command:

        ::

            # ip ecmp disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ecmp disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Completely disable ECMP

        This function runs the following vtysh command:

        ::

            # no ip ecmp disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ecmp disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_dst_ip_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by destination IP

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance dst-ip disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ecmp load-balance dst-ip disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_dst_ip_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by destination IP

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance dst-ip disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ecmp load-balance dst-ip disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_dst_port_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by destination port

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance dst-port disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ecmp load-balance dst-port disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_dst_port_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by destination port

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance dst-port disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ecmp load-balance dst-port disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_src_port_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by source port

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance src-port disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ecmp load-balance src-port disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_src_port_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by source port

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance src-port disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ecmp load-balance src-port disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_src_ip_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by source IP

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance src-ip disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ecmp load-balance src-ip disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_src_ip_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable load balancing by source IP

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance src-ip disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ecmp load-balance src-ip disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ecmp_load_balance_resilient_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable resilient hashing for load balancing

        This function runs the following vtysh command:

        ::

            # ip ecmp load-balance resilient disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ecmp load-balance resilient disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ecmp_load_balance_resilient_disable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable resilient hashing for load balancing

        This function runs the following vtysh command:

        ::

            # no ip ecmp load-balance resilient disable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ecmp load-balance resilient disable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sftp_server_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable sftp server.

        This function runs the following vtysh command:

        ::

            # sftp server enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sftp server enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sftp_server_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable sftp server.

        This function runs the following vtysh command:

        ::

            # no sftp server enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sftp server enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server(
        self, host,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        NTP Association configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host}

        :param host: NTP Association name or IPv4 Address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp server {host}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_server(
        self, host,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove NTP association

        This function runs the following vtysh command:

        ::

            # no ntp server {host}

        :param host: NTP Association name or IPv4 Address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ntp server {host}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server_prefer(
        self, host,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Add NTP Association preference configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host} prefer

        :param host: NTP Association name or IPv4 Address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp server {host} prefer'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server_key_id(
        self, host, key_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Add NTP Key ID

        This function runs the following vtysh command:

        ::

            # ntp server {host} key-id {key_id}

        :param host: NTP Association name or IPv4 Address.
        :param key_id: WORD  NTP Key Number between 1-65534
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp server {host} key-id {key_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_server_version(
        self, host, version,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Add NTP Association version configuration

        This function runs the following vtysh command:

        ::

            # ntp server {host} version {version}

        :param host: NTP Association name or IPv4 Address.
        :param version: WORD  Version can be 3 or 4
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp server {host} version {version}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_authentication_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable NTP Authentication configuration

        This function runs the following vtysh command:

        ::

            # ntp authentication enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp authentication enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_authentication_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable NTP Authentication configuration

        This function runs the following vtysh command:

        ::

            # no ntp authentication enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ntp authentication enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_authentication_key_md5(
        self, key_id, password,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Add NTP Authentication Key

        This function runs the following vtysh command:

        ::

            # ntp authentication-key {key_id} md5 {password}

        :param key_id: WORD  NTP Key Number between 1-65534
        :param password: WORD  NTP MD5 Password <8-16> chars
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp authentication-key {key_id} md5 {password}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_authentication_key(
        self, key_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove NTP Authentication Key

        This function runs the following vtysh command:

        ::

            # no ntp authentication-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ntp authentication-key {key_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ntp_trusted_key(
        self, key_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Add NTP Trusted Key

        This function runs the following vtysh command:

        ::

            # ntp trusted-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ntp trusted-key {key_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ntp_trusted_key(
        self, key_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove NTP Trusted Key

        This function runs the following vtysh command:

        ::

            # no ntp trusted-key {key_id}

        :param key_id: WORD  NTP Key Number between 1-65534
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ntp trusted-key {key_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def logging(
        self, remote_host, transport='', severity='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_logging(
        self, remote_host, transport='', severity='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlog_daemon(
        self, daemon, destination, severity,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure the daemon

        This function runs the following vtysh command:

        ::

            # vlog daemon {daemon} {destination} {severity}

        :param daemon: daemon name
        :param destination: configure the log level of destination
        :param severity: severity level
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlog daemon {daemon} {destination} {severity}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlog_feature(
        self, feature, destination, severity,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure the feature

        This function runs the following vtysh command:

        ::

            # vlog feature {feature} {destination} {severity}

        :param feature: feature name
        :param destination: configure the log level of destination
        :param severity: severity level
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlog feature {feature} {destination} {severity}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def logrotate_period(
        self, time_interval,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set Logrotate time interval.

        This function runs the following vtysh command:

        ::

            # logrotate period {time_interval}

        :param time_interval: rotates log files time interval
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'logrotate period {time_interval}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def logrotate_maxsize(
        self, file_size,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set Logrotate maxsize of file.

        This function runs the following vtysh command:

        ::

            # logrotate maxsize {file_size}

        :param file_size: <1-200>  File size in Mega Bytes
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'logrotate maxsize {file_size}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def logrotate_target(
        self, tftp_host,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set Logrotate tftp remote host.

        This function runs the following vtysh command:

        ::

            # logrotate target {tftp_host}

        :param tftp_host: URI of the remote host
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'logrotate target {tftp_host}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_community(
        self, community_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP community names

        This function runs the following vtysh command:

        ::

            # snmp-server community {community_name}

        :param community_name: Configured Community names
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server community {community_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_community(
        self, community_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP community names

        This function runs the following vtysh command:

        ::

            # no snmp-server community

        :param community_name: Unconfigured community names
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_system_contact(
        self, system_contact,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP system contact information

        This function runs the following vtysh command:

        ::

            # snmp-server system-contact {system_contact}

        :param system_contact: Configured System contact information
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server system-contact {system_contact}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_system_contact(
        self, system_contact='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP contact information

        This function runs the following vtysh command:

        ::

            # no snmp-server system-contact

        :param system_contact: Unconfigure system contact information
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_system_location(
        self, system_location,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP system location information

        This function runs the following vtysh command:

        ::

            # snmp-server system-location {system_location}

        :param system_location: Configured System location information
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server system-location {system_location}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_system_location(
        self, system_location='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP location information

        This function runs the following vtysh command:

        ::

            # no snmp-server system-location

        :param system_location: Unconfigure system location information
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_system_description(
        self, system_description,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP system description

        This function runs the following vtysh command:

        ::

            # snmp-server system-description                {system_description} # noqa

        :param system_description: Configured System description
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server system-description                {system_description}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_system_description(
        self, system_desription='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP system description

        This function runs the following vtysh command:

        ::

            # no snmp-server system-description

        :param system_desription: Unconfigure system description
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_host_trap_version(
        self, host_ip_address, snmp_version, community='',
        community_name='', port='', snmp_port='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP server information for trap receiver

        This function runs the following vtysh command:

        ::

            # snmp-server host {host_ip_address} trap version {snmp_version}

        :param host_ip_address: Configured host ip address for trap receiver
        :param snmp_version: Configured snmp version for receiver
        :param community: Configured snmp community name for trap
            receiver
        :param community_name: Configured snmp community name for trap
            receiver
        :param port: Configured snmp port for trap receiver
        :param snmp_port: Configured snmp port for trap receiver
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server host {host_ip_address} trap version {snmp_version}'
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community_name:
            cmd.append(
                '{}{{community_name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp_port:
            cmd.append(
                '{}{{snmp_port}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_host_trap_version(
        self, host_ip_address, snmp_version, community='',
        community_name='', port='', snmp_port='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP server information for trap receiver

        This function runs the following vtysh command:

        ::

            # no snmp-server host {host_ip_address} trap version {snmp_version}

        :param host_ip_address: Unconfigured host ip address for trap
            receiver
        :param snmp_version: Unconfigured snmp version for receiver
        :param community: Unconfigured snmp community name for trap
            receiver
        :param community_name: Unconfigured snmp community name for trap
            receiver
        :param port: Unconfigured snmp port for trap receiver
        :param snmp_port: Unconfigured snmp port for trap receiver
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no snmp-server host {host_ip_address} trap version {snmp_version}'
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community_name:
            cmd.append(
                '{}{{community_name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp_port:
            cmd.append(
                '{}{{snmp_port}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_host_inform_version(
        self, host_ip_address, snmp_version, community='',
        community_name='', port='', snmp_port='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP server information for notifications

        This function runs the following vtysh command:

        ::

            # snmp-server host {host_ip_address} inform version {snmp_version}

        :param host_ip_address: Configured host ip address for notifications
        :param snmp_version: Configured snmp version for notifications
        :param community: Configured snmp community name for
            notifications
        :param community_name: Configured snmp community name for
            notifications
        :param port: Configured snmp port for notifications
        :param snmp_port: Configured snmp port for notifications
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server host {host_ip_address} inform version {snmp_version}'
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community_name:
            cmd.append(
                '{}{{community_name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp_port:
            cmd.append(
                '{}{{snmp_port}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_host_inform_version(
        self, host_ip_address, snmp_version, community='',
        community_name='', port='', snmp_port='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP server information for notifications

        This function runs the following vtysh command:

        ::

            # no snmp-server host {host_ip_address} inform version {snmp_version} # noqa

        :param host_ip_address: Unconfigured host ip address for
            notifications
        :param snmp_version: Unconfigured snmp version for notifications
        :param community: Unconfigured snmp community name for
            notifications
        :param community_name: Unconfigured snmp community name for
            notifications
        :param port: Unconfigured snmp port for notifications
        :param snmp_port: Unconfigured snmp port for notifications
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'no snmp-server host {host_ip_address} inform version {snmp_version}'  # noqa
        ]

        if community:
            cmd.append(
                '{}{{community}}{}'.format(
                    '', ''
                )
            )

        if community_name:
            cmd.append(
                '{}{{community_name}}{}'.format(
                    '', ''
                )
            )

        if port:
            cmd.append(
                '{}{{port}}{}'.format(
                    '', ''
                )
            )

        if snmp_port:
            cmd.append(
                '{}{{snmp_port}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmpv3_user(
        self, user_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMPv3 user name

        This function runs the following vtysh command:

        ::

            # snmpv3 user {user_name}

        :param user-name: Configured user_name for SNMPv3
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmpv3 user {user_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmpv3_user(
        self, user_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMPv3 user name

        This function runs the following vtysh command:

        ::

            # no snmpv3 user {user_name}

        :param user_name: Unconfigured SNMPv3 user name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no snmpv3 user {user_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmpv3_user_auth_auth_pass(
        self, user_name, auth_protocol, auth_password,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password} # noqa

        :param user_name: Configured user-name for SNMPv3
        :param auth_protocol: Configured auth protocol for SNMPv3 user
        :param auth_password: Configured auth password for SNMPv3 user
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmpv3_user_auth_auth_pass(
        self, user_name, auth_protocol, auth_password,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # no snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password} # noqa

        :param user_name: Unconfigured user-name for SNMPv3
        :param auth_protocol: Unconfigured auth protocol for SNMPv3 user
        :param auth_password: Unconfigured auth password for SNMPv3 user
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'no snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmpv3_user_auth_auth_pass_priv_priv_pass(
        self, user_name, auth_protocol, auth_password,
        priv_protocol, priv_password,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password} priv {priv_protocol} priv-pass {priv_password} # noqa

        :param user_name: Configured user-name for SNMPv3
        :param auth_protocol: Configured auth protocol for SNMPv3 user
        :param auth_password: Configured auth password for SNMPv3 user
        :param priv_protocol: Configured priv protocol for SNMPv3 user
        :param priv_password: Configured priv password for SNMPv3 user
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password} priv {priv_protocol} priv-pass {priv_password}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmpv3_user_auth_auth_pass_priv_priv_pass(
        self, user_name, auth_protocol, auth_password,
        priv_protocol, priv_password,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMPv3 user name with auth protocol and
        password

        This function runs the following vtysh command:

        ::

            # no snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password} priv {priv_protocol} priv-pass {priv_password} # noqa

        :param user_name: Unconfigured user-name for SNMPv3
        :param auth_protocol: Unconfigured auth protocol for SNMPv3 user
        :param auth_password: Unconfigured auth password for SNMPv3 user
        :param priv_protocol: Unconfigured priv protocol for SNMPv3 user
        :param priv_password: Unconfigured priv password for SNMPv3 user
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'no snmpv3 user {user_name} auth {auth_protocol} auth-pass {auth_password} priv {priv_protocol} priv-pass {priv_password}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def snmp_server_agent_port(
        self, port_num,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure SNMP agent port

        This function runs the following vtysh command:

        ::

            # snmp-server agent-port {port_num}

        :param port_num: UDP port on which the SNMP agent listens
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'snmp-server agent-port {port_num}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_snmp_server_agent_port(
        self, port_num='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure SNMP agent port

        This function runs the following vtysh command:

        ::

            # no snmp-server agent-port

        :param port_num: UDP port on which the SNMP agent listens
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no snmp-server agent-port'
        ]

        if port_num:
            cmd.append(
                '{}{{port_num}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_mirror_session(
        self, name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Delete a mirroring session.

        This function runs the following vtysh command:

        ::

            # no mirror session {name}

        :param name: Up to 64 letters, numbers, underscores, dashes, or
            periods.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no mirror session {name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enables MSTP feature for all the instances

        This function runs the following vtysh command:

        ::

            # spanning-tree

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disables MSTP feature for all the instances

        This function runs the following vtysh command:

        ::

            # no spanning-tree

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_config_name(
        self, configuration_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets config name for MSTP

        This function runs the following vtysh command:

        ::

            # spanning-tree config-name {configuration_name}

        :param configuration_name: Specifies the MSTP configuration name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree config-name {configuration_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_config_name(
        self, configuration_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the default config name for all the instances, default is system
        MAC-Address

        This function runs the following vtysh command:

        ::

            # no spanning-tree config-name

        :param configuration_name: Specifies the MSTP configuration name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree config-name'
        ]

        if configuration_name:
            cmd.append(
                '{}{{configuration_name}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_config_revision(
        self, revision_number,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets config revision number for the all the instances

        This function runs the following vtysh command:

        ::

            # spanning-tree config-revision {revision_number}

        :param revision_number: Specifies the MSTP configuration revision
            number value <1-40>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree config-revision {revision_number}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_config_revision(
        self, revision_number='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets default config revision number for the all the instances, default
        value is 0

        This function runs the following vtysh command:

        ::

            # no spanning-tree config-revision

        :param revision_number: Specifies the MSTP configuration revision
            number value <1-40>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree config-revision'
        ]

        if revision_number:
            cmd.append(
                '{}{{revision_number}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_instance_vlan(
        self, instance_id, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Maps the VLAN-ID to corresponding instance

        This function runs the following vtysh command:

        ::

            # spanning-tree instance {instance_id} vlan {vlan_id}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param vlan_id: Specifies the VLAN-ID number <1-4094>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree instance {instance_id} vlan {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_instance_vlan(
        self, instance_id, vlan_id='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the VLAN-ID from the MSTP instance

        This function runs the following vtysh command:

        ::

            # no spanning-tree instance {instance_id} vlan

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param vlan_id: Specifies the VLAN-ID number <1-4094>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree instance {instance_id} vlan'
        ]

        if vlan_id:
            cmd.append(
                '{}{{vlan_id}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_instance_priority(
        self, instance_id, priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Maps the priority to corresponding instance

        This function runs the following vtysh command:

        ::

            # spanning-tree instance {instance_id} priority {priority}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param priority: The device priority multiplier for the MST instance
            <0-15>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree instance {instance_id} priority {priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_instance_priority(
        self, instance_id, priority='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the priority from the MSTP instance

        This function runs the following vtysh command:

        ::

            # no spanning-tree instance {instance_id} priority

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param priority: The device priority multiplier for the MST instance
            <0-15>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree instance {instance_id} priority'
        ]

        if priority:
            cmd.append(
                '{}{{priority}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_instance(
        self, instance_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the MSTP instance

        This function runs the following vtysh command:

        ::

            # no spanning-tree instance {instance_id}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree instance {instance_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_forward_delay(
        self, delay_in_secs,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the forward-delay for all the MSTP instances

        This function runs the following vtysh command:

        ::

            # spanning-tree forward-delay {delay_in_secs}

        :param delay_in_secs: Specifies the forward delay in seconds <4-30>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree forward-delay {delay_in_secs}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_forward_delay(
        self, delay_in_secs='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the default forward-delay for all the MSTP instances, default
        value is 15 seconds

        This function runs the following vtysh command:

        ::

            # no spanning-tree forward-delay

        :param delay_in_secs: Specifies the forward delay in seconds <4-30>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree forward-delay'
        ]

        if delay_in_secs:
            cmd.append(
                '{}{{delay_in_secs}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_hello_time(
        self, hello_in_secs,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the hello interval for all the MSTP instances

        This function runs the following vtysh command:

        ::

            # spanning-tree hello-time {hello_in_secs}

        :param hello_in_secs: Specifies the hello interval in seconds <2-10>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree hello-time {hello_in_secs}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_hello_time(
        self, hello_in_secs='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the default hello interval for all the MSTP instances, default
        value is 2 seconds

        This function runs the following vtysh command:

        ::

            # no spanning-tree hello-time

        :param hello_in_secs: Specifies the hello interval in seconds <2-10>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree hello-time'
        ]

        if hello_in_secs:
            cmd.append(
                '{}{{hello_in_secs}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_max_age(
        self, age_in_secs,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the maximum age for all the MSTP instances

        This function runs the following vtysh command:

        ::

            # spanning-tree max-age {age_in_secs}

        :param age_in_secs: Specifies the maximum age in seconds <6-30>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree max-age {age_in_secs}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_max_age(
        self, age_in_secs='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the default max age for all the MSTP instances, default value is
        20 seconds

        This function runs the following vtysh command:

        ::

            # no spanning-tree max-age

        :param age_in_secs: Specifies the maximum age in seconds <6-30>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree max-age'
        ]

        if age_in_secs:
            cmd.append(
                '{}{{age_in_secs}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_max_hops(
        self, hop_count,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the hop count for all the MSTP instances

        This function runs the following vtysh command:

        ::

            # spanning-tree max-hops {hop_count}

        :param hop_count: Specifies the maximum number of hops <1-40>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree max-hops {hop_count}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_max_hops(
        self, hop_count='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the default hop count for all the MSTP instances, default value is
        20

        This function runs the following vtysh command:

        ::

            # no spanning-tree max-hops

        :param hop_count: Specifies the maximum number of hops <1-40>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree max-hops'
        ]

        if hop_count:
            cmd.append(
                '{}{{hop_count}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_priority(
        self, priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the device priority multiplier

        This function runs the following vtysh command:

        ::

            # spanning-tree priority {priority}

        :param priority: Device priority multiplier <0-15>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree priority {priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_priority(
        self, priority='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the device priority multiplier

        This function runs the following vtysh command:

        ::

            # no spanning-tree priority

        :param priority: Device priority multiplier <0-15>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree priority'
        ]

        if priority:
            cmd.append(
                '{}{{priority}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_transmit_hold_count(
        self, count,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the transmit hold count performance parameter in pps

        This function runs the following vtysh command:

        ::

            # spanning-tree transmit-hold-count {count}

        :param count: Transmit hold count <1-10>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree transmit-hold-count {count}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_transmit_hold_count(
        self, count='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the transmit hold count performance parameter in pps

        This function runs the following vtysh command:

        ::

            # no spanning-tree transmit-hold-count

        :param count: Transmit hold count <1-10>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree transmit-hold-count'
        ]

        if count:
            cmd.append(
                '{}{{count}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def access_list_ip(
        self, access_list,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure access list.

        This function runs the following vtysh command:

        ::

            # access-list ip {access_list}

        :param access_list: Access List Name.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'access-list ip {access_list}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_access_list_ip(
        self, access_list,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure access list.

        This function runs the following vtysh command:

        ::

            # no access-list ip {access_list}

        :param access_list: Access List Name.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no access-list ip {access_list}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def access_list_ip_resequence(
        self, access_list, start, increment,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Resequence ACL Lists.

        This function runs the following vtysh command:

        ::

            # access-list ip {access_list} resequence {start} {increment}

        :param access_list: Access List Name.
        :param start: beginning index of entry in access list
        :param increment: increment factor of subsequent ACE in ACL
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'access-list ip {access_list} resequence {start} {increment}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def access_list_log_timer(
        self, seconds,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure ACL Log Timer value.

        This function runs the following vtysh command:

        ::

            # access-list log-timer {seconds}

        :param seconds: <30-300>Specify value(seconds) or default.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'access-list log-timer {seconds}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def radius_server_host_auth_port(
        self, ip_addr, port,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Radius server auth-port configuration

        This function runs the following vtysh command:

        ::

            # radius-server host {ip_addr} auth-port {port}

        :param ip_addr: Radius server IPv4 address
        :param port: <0-65535>  UDP port range is 0 to 65535
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'radius-server host {ip_addr} auth-port {port}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_radius_server_host_auth_port(
        self, ip_addr, port,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Radius server auth-port configuration

        This function runs the following vtysh command:

        ::

            # no radius-server host {ip_addr} auth-port {port}

        :param ip_addr: Radius server IPv4 address
        :param port: <0-65535>  UDP port range is 0 to 65535
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no radius-server host {ip_addr} auth-port {port}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def radius_server_host_key(
        self, ip_addr, secret,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Radius server key configuration

        This function runs the following vtysh command:

        ::

            # radius-server host {ip_addr} key {secret}

        :param ip_addr: Radius server IPv4 address
        :param secret: WORD Radius shared secret
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'radius-server host {ip_addr} key {secret}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_radius_server_host_key(
        self, ip_addr, secret,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Radius server key configuration

        This function runs the following vtysh command:

        ::

            # no radius-server host {ip_addr} key {secret}

        :param ip_addr: Radius server IPv4 address
        :param secret: WORD Radius shared secret
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no radius-server host {ip_addr} key {secret}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def radius_server_host(
        self, ip_addr,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Radius server configuration

        This function runs the following vtysh command:

        ::

            # radius-server host {ip_addr}

        :param ip_addr: Radius server IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'radius-server host {ip_addr}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_radius_server_host(
        self, ip_addr,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Radius server configuration

        This function runs the following vtysh command:

        ::

            # no radius-server host {ip_addr}

        :param ip_addr: Radius server IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no radius-server host {ip_addr}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def aaa_authentication_login(
        self, type,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        AAA authentication login configuration

        This function runs the following vtysh command:

        ::

            # aaa authentication login {type}

        :param type: local Local authenticationradius Radius authentication
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'aaa authentication login {type}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def aaa_authentication_login_fallback_error_local(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        AAA authentication login fallback configuration

        This function runs the following vtysh command:

        ::

            # aaa authentication login fallback error local

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'aaa authentication login fallback error local'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def timezone_set(
        self, timezone,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the system timezone

        This function runs the following vtysh command:

        ::

            # timezone set {timezone}

        :param timezone: Available timezone from list
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'timezone set {timezone}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_timezone_set(
        self, timezone,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the system timezone

        This function runs the following vtysh command:

        ::

            # no timezone set {timezone}

        :param timezone: Available timezone from list
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no timezone set {timezone}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, description,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set description

        This function runs the following vtysh command:

        ::

            # description {description}

        :param description: LINE  Comment describing this route-map rule
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'description {description}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_description(
        self, description,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset description

        This function runs the following vtysh command:

        ::

            # no description {description}

        :param description: LINE  Comment describing this route-map rule
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no description {description}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def match_ip_address_prefix_list(
        self, prefix_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set prefix-list

        This function runs the following vtysh command:

        ::

            # match ip address prefix-list {prefix_name}

        :param prefix_name: WORD  IP prefix-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'match ip address prefix-list {prefix_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_match_ip_address_prefix_list(
        self, prefix_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset prefix-list

        This function runs the following vtysh command:

        ::

            # no match ip address prefix-list

        :param prefix_name: WORD  IP prefix-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def set_metric(
        self, metric,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set metric

        This function runs the following vtysh command:

        ::

            # set metric {metric}

        :param metric: <0-4294967295>  Metric value
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'set metric {metric}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_set_metric(
        self, metric='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset metric

        This function runs the following vtysh command:

        ::

            # no set metric

        :param metric: <0-4294967295>  Metric value
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def set_community(
        self, community,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set community

        This function runs the following vtysh command:

        ::

            # set community {community}

        :param community: AA:NN  Community number in aa:nn format or local-AS
            \|no-advertise\|no-export\|internet or additive
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'set community {community}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_set_community(
        self, community='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset community

        This function runs the following vtysh command:

        ::

            # no set community

        :param community: AA:NN  Community number in aa:nn format orlocal-AS
            \|no-advertise\|no-export\|internet or additive
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def set_as_path_exclude(
        self, as_path,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set as-path exclude

        This function runs the following vtysh command:

        ::

            # set as-path exclude {as_path}

        :param as_path: <1-4294967295>  AS number
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'set as-path exclude {as_path}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_set_as_path_exclude(
        self, as_path='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset set as-path exclude

        This function runs the following vtysh command:

        ::

            # no set as-path exclude

        :param as_path: <1-4294967295>  AS number
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no set as-path exclude'
        ]

        if as_path:
            cmd.append(
                '{}{{as_path}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Mapping port to vrf

        This function runs the following vtysh command:

        ::

            # vrf attach {vrf_name}

        :param vrf_name: Mapping the port to vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unmapping port from vrf

        This function runs the following vtysh command:

        ::

            # no vrf attach {vrf_name}

        :param vrf_name: Unmapping the port from vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_authentication_message_digest(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure OSPF MD5 authentication

        This function runs the following vtysh command:

        ::

            # ip ospf authentication message-digest

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf authentication message-digest'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_authentication(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure OSPF text authentication

        This function runs the following vtysh command:

        ::

            # ip ospf authentication

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf authentication'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ospf_authentication(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove OSPF text authentication

        This function runs the following vtysh command:

        ::

            # no ip ospf authentication

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ospf authentication'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_message_digest_key_md5(
        self, key_id, password_key,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring MD5 authentication with encryption

        This function runs the following vtysh command:

        ::

            # ip ospf message-digest-key {key_id} md5 {password_key}

        :param key_id: <1-255> key_id range
        :param password_key: OSPF password key
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf message-digest-key {key_id} md5 {password_key}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ospf_message_digest_key(
        self, key_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removing MD5 authentication with encryption

        This function runs the following vtysh command:

        ::

            # no ip ospf message-digest-key {key_id}

        :param key_id: <1-255> key_id range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ospf message-digest-key {key_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_authentication_key(
        self, auth_key,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring text authentication with encryption

        This function runs the following vtysh command:

        ::

            # ip ospf authentication-key {auth_key}

        :param auth_key: Text authentication Authorization key
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf authentication-key {auth_key}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_ospf_authentication_key(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removing text authentication with encryption

        This function runs the following vtysh command:

        ::

            # no ip ospf authentication-key

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip ospf authentication-key'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def routing(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure interface as L3.

        This function runs the following vtysh command:

        ::

            # routing

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'routing'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_routing(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure interface as L3.

        This function runs the following vtysh command:

        ::

            # no routing

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no routing'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_access(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Access configuration

        This function runs the following vtysh command:

        ::

            # vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan access {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_access(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove vlan access

        This function runs the following vtysh command:

        ::

            # no vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan access {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_allowed(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Allow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan trunk allowed {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_allowed(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disallow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan trunk allowed {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native_tag(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native tag

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan trunk native tag'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native_tag(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native tag

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan trunk native tag'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan trunk native {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan trunk native {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_port_id(
        self, port_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set port ID used in LACP negotiation.

        This function runs the following vtysh command:

        ::

            # lacp port-id {port_id}

        :param port_id: <1-65535>  .The range is 1 to 65535
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp port-id {port_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_dead_interval(
        self, dead_timer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure ospf dead_timer

        This function runs the following vtysh command:

        ::

            # ip ospf dead-interval {dead_timer}

        :param dead_timer: <1-65535>  dead_timer range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf dead-interval {dead_timer}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_hello_interval(
        self, hello_timer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure ospf hello_timer

        This function runs the following vtysh command:

        ::

            # ip ospf hello-interval {hello_timer}

        :param hello_timer: <10-30>  hello interval range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf hello-interval {hello_timer}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_ospf_priority(
        self, ospf_priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure ospf priority

        This function runs the following vtysh command:

        ::

            # ip ospf priority {ospf_priority}

        :param ospf_priority: <0-255>  . The range is 0 to 255
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip ospf priority {ospf_priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_port_priority(
        self, port_priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set port priority is used in LACP negotiation.

        This function runs the following vtysh command:

        ::

            # lacp port-priority {port_priority}

        :param port_priority: <1-65535>  The range is 1 to 65535
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp port-priority {port_priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lag(
        self, lag_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Add the current interface to link aggregation.

        This function runs the following vtysh command:

        ::

            # lag {lag_id}

        :param lag_id: <1-2000>  LAG number ranges from 1 to 2000
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lag {lag_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lag(
        self, lag_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the current interface to link aggregation.

        This function runs the following vtysh command:

        ::

            # no lag {lag_id}

        :param lag_id: <1-2000>  LAG number ranges from 1 to 2000
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lag {lag_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_transmit(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the transmission on lldp.

        This function runs the following vtysh command:

        ::

            # lldp transmit

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp transmit'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_transmit(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-set the transmission on lldp.

        This function runs the following vtysh command:

        ::

            # no lldp transmit

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp transmit'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lldp_receive(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the reception on lldp.

        This function runs the following vtysh command:

        ::

            # lldp receive

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lldp receive'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lldp_receive(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-set the reception on lldp.

        This function runs the following vtysh command:

        ::

            # no lldp receive

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lldp receive'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def udld_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable UDLD in the interface.

        This function runs the following vtysh command:

        ::

            # udld enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'udld enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_udld_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable UDLD in the interface.

        This function runs the following vtysh command:

        ::

            # no udld enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no udld enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def udld_interval(
        self, interval,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the packet interval

        This function runs the following vtysh command:

        ::

            # udld interval {interval}

        :param interval: <100-10000> Allowed is 100 ms to 10,000 ms
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'udld interval {interval}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def udld_retries(
        self, retries,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the retries

        This function runs the following vtysh command:

        ::

            # udld retries {retries}

        :param retries: <3-10> Allowed is from 3 to 10 retries.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'udld retries {retries}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def udld_mode(
        self, mode,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the operation mode

        This function runs the following vtysh command:

        ::

            # udld mode {mode}

        :param mode: <forward_then_verify | verify_then_forward>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'udld mode {mode}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def sflow_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable sflow feature on interface

        This function runs the following vtysh command:

        ::

            # sflow enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'sflow enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_sflow_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable sflow feature on interface

        This function runs the following vtysh command:

        ::

            # no sflow enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no sflow enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def split(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Split parent interface

        This function runs the following vtysh command:

        ::

            # split

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'split'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_split(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable split parent interface

        This function runs the following vtysh command:

        ::

            # no split

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no split'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def n(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Send 'n' when waiting confirmation for split

        This function runs the following vtysh command:

        ::

            # n

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'n'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def y(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Send 'y' when waiting confirmation for split

        This function runs the following vtysh command:

        ::

            # y

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'y'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def autonegotiation_on(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Autonegotiation ON

        This function runs the following vtysh command:

        ::

            # autonegotiation on

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'autonegotiation on'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def autonegotiation_off(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Autonegotiation OFF

        This function runs the following vtysh command:

        ::

            # autonegotiation off

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'autonegotiation off'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_autonegotiation(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable autonegotiation

        This function runs the following vtysh command:

        ::

            # no autonegotiation

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no autonegotiation'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_port_type(
        self, admin_type,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the port-type for all the MSTP instances

        This function runs the following vtysh command:

        ::

            # spanning-tree port-type {admin_type}

        :param admin_type: admin-edge Specifies the port as admin-edge
            admin-
            network Specifies the port as admin-network
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree port-type {admin_type}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_port_type(
        self, admin_type='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the port-type for all the MSTP instances

        This function runs the following vtysh command:

        ::

            # no spanning-tree port-type {admin_type}

        :param admin_type: admin-edge Specifies the port as admin-edge
            admin-
            network Specifies the port as admin-network
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree port-type {admin_type}'
        ]

        if admin_type:
            cmd.append(
                '{}{{admin_type}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_bpdu_guard(
        self, action,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the bpdu guard on the interfaces

        This function runs the following vtysh command:

        ::

            # spanning-tree bpdu-guard {action}

        :param action: enable Enable the bpdu guard on the interfacesdisable
            Disable the bpdu guard on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree bpdu-guard {action}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_bpdu_guard(
        self, action='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the bpdu guard on the interfaces

        This function runs the following vtysh command:

        ::

            # no spanning-tree bpdu-guard {action}

        :param action: enable Enable the bpdu guard on the interfacesdisable
            Disable the bpdu guard on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree bpdu-guard {action}'
        ]

        if action:
            cmd.append(
                '{}{{action}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_root_guard(
        self, action,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the root guard on the interfaces

        This function runs the following vtysh command:

        ::

            # spanning-tree root-guard {action}

        :param action: enable Enable the root guard on the interfacesdisable
            Disable the root guard on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree root-guard {action}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_root_guard(
        self, action='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the root guard on the interfaces

        This function runs the following vtysh command:

        ::

            # no spanning-tree root-guard {action}

        :param action: enable Enable the root guard on the interfacesdisable
            Disable the root guard on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree root-guard {action}'
        ]

        if action:
            cmd.append(
                '{}{{action}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_loop_guard(
        self, action,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the loop guard on the interfaces

        This function runs the following vtysh command:

        ::

            # spanning-tree loop-guard {action}

        :param action: enable Enable the loop guard on the interfacesdisable
            Disable the loop guard on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree loop-guard {action}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_loop_guard(
        self, action='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the loop guard on the interfaces

        This function runs the following vtysh command:

        ::

            # no spanning-tree loop-guard {action}

        :param action: enable Enable the loop guard on the interfacesdisable
            Disable the loop guard on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree loop-guard {action}'
        ]

        if action:
            cmd.append(
                '{}{{action}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_bpdu_filter(
        self, action,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the bpdu filter on the interfaces

        This function runs the following vtysh command:

        ::

            # spanning-tree bpdu-filter {action}

        :param action: enable Enable the bpdu filter on the interfacesdisable
            Disable the bpdu filter on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree bpdu-filter {action}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_bpdu_filter(
        self, action='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable/Disable the bpdu filter on the interfaces

        This function runs the following vtysh command:

        ::

            # no spanning-tree bpdu-filter {action}

        :param action: enable Enable the bpdu filter on the interfacesdisable
            Disable the bpdu filter on the interfaces
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree bpdu-filter {action}'
        ]

        if action:
            cmd.append(
                '{}{{action}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_instance_cost(
        self, instance_id, cost,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Specify a standard to use when calculating the default pathcost

        This function runs the following vtysh command:

        ::

            # spanning-tree instance {instance_id} cost {cost}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param cost: Path cost range <1-200000000>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree instance {instance_id} cost {cost}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_instance_cost(
        self, instance_id, cost='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Specify a standard to use when calculating the default pathcost

        This function runs the following vtysh command:

        ::

            # no spanning-tree instance {instance_id} cost {cost}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param cost: Path cost range <1-200000000>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree instance {instance_id} cost {cost}'
        ]

        if cost:
            cmd.append(
                '{}{{cost}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def spanning_tree_instance_port_priority(
        self, instance_id, priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Maps the priority to corresponding instance

        This function runs the following vtysh command:

        ::

            # spanning-tree instance {instance_id} port-priority {priority}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param priority: The device priority multiplier for the MST instance
            <0-15>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'spanning-tree instance {instance_id} port-priority {priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_spanning_tree_instance_port_priority(
        self, instance_id, priority='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the port-priority from the MSTP instance

        This function runs the following vtysh command:

        ::

            # no spanning-tree instance {instance_id} port-priority {priority}

        :param instance_id: Specifies the MSTP instance number <1-64>
        :param priority: The device priority multiplier for the MST instance
            <0-15>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no spanning-tree instance {instance_id} port-priority {priority}'
        ]

        if priority:
            cmd.append(
                '{}{{priority}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_qos_schedule_profile(
        self, schedule_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply qos profiles on an interface.

        This function runs the following vtysh command:

        ::

            # apply qos schedule-profile {schedule_profile_name}

        :param schedule_profile_name: The schedule profile to apply.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'apply qos schedule-profile {schedule_profile_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_apply_qos_schedule_profile(
        self, schedule_profile_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clears qos profiles from an interface.

        This function runs the following vtysh command:

        ::

            # no apply qos schedule-profile

        :param schedule_profile_name: The schedule profile to clear.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no apply qos schedule-profile'
        ]

        if schedule_profile_name:
            cmd.append(
                '{}{{schedule_profile_name}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp(
        self, dscp_map_index,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the dscp override for the port.

        This function runs the following vtysh command:

        ::

            # qos dscp {dscp_map_index}

        :param dscp_map_index: The index into the dscp map.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos dscp {dscp_map_index}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_dscp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the dscp override for the port.

        This function runs the following vtysh command:

        ::

            # no qos dscp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos dscp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_trust(
        self, value,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the qos trust mode for the port.

        This function runs the following vtysh command:

        ::

            # qos trust {value}

        :param value: The qos trust mode to set.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos trust {value}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_trust(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the qos trust mode for the port.

        This function runs the following vtysh command:

        ::

            # no qos trust

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos trust'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_access_list_ip_in(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply ACL on interface to ingress traffic

        This function runs the following vtysh command:

        ::

            # apply access-list ip {acl_name} in

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'apply access-list ip {acl_name} in'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_apply_access_list_ip_in(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply no ACL on interface to ingress traffic

        This function runs the following vtysh command:

        ::

            # no apply access-list ip {acl_name} in

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no apply access-list ip {acl_name} in'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_access_list_ip_out(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply ACL on interface to egress traffic

        This function runs the following vtysh command:

        ::

            # apply access-list ip {acl_name} out

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'apply access-list ip {acl_name} out'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_apply_access_list_ip_out(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply no ACL on interface to egress traffic

        This function runs the following vtysh command:

        ::

            # no apply access-list ip {acl_name} out

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no apply access-list ip {acl_name} out'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vrrp_address_family(
        self, grpid, af,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VRRP virtual router id and address-family

        This function runs the following vtysh command:

        ::

            # vrrp {grpid} address-family {af}

        :param grpid: Virtual router id <1-255>
        :param af: Address family <ipv4|ipv6>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vrrp {grpid} address-family {af}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vrrp_address_family(
        self, grpid, af,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove VRRP virtual router id and address-family

        This function runs the following vtysh command:

        ::

            # no vrrp {grpid} address-family {af}

        :param grpid: Virtual router id <1-255>
        :param af: Address family <ipv4|ipv6>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vrrp {grpid} address-family {af}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def mtu(
        self, mtu_size,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set MTU

        This function runs the following vtysh command:

        ::

            # mtu {mtu_size}

        :param mtu_size: MTU in bytes range <576-9192>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'mtu {mtu_size}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_mtu(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset MTU

        This function runs the following vtysh command:

        ::

            # no mtu

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no mtu'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Subinterface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Subinterface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Mapping port to vrf

        This function runs the following vtysh command:

        ::

            # vrf attach {vrf_name}

        :param vrf_name: Mapping the port to vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unmapping port from vrf

        This function runs the following vtysh command:

        ::

            # no vrf attach {vrf_name}

        :param vrf_name: Unmapping the port from vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Subinterface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Subinterface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def encapsulation_dot1_q(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set encapsulation type for a subinterface

        This function runs the following vtysh command:

        ::

            # encapsulation dot1Q {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'encapsulation dot1Q {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_encapsulation_dot1_q(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset encapsulation type for a subinterface

        This function runs the following vtysh command:

        ::

            # no encapsulation dot1Q {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no encapsulation dot1Q {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable a subinterface.

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable a subinterface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IPv4 address for loopback

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Loopback IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv4 address for loopback

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Loopback IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Mapping port to vrf

        This function runs the following vtysh command:

        ::

            # vrf attach {vrf_name}

        :param vrf_name: Mapping the port to vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unmapping port from vrf

        This function runs the following vtysh command:

        ::

            # no vrf attach {vrf_name}

        :param vrf_name: Unmapping the port from vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IPv6 address on Loopback

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Loopback IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address on loopback interface

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Loopback IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4}

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set secondary IP address

        This function runs the following vtysh command:

        ::

            # ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset secondary IP address

        This function runs the following vtysh command:

        ::

            # no ip address {ipv4} secondary

        :param ipv4: A.B.C.D/M Interface IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Mapping port to vrf

        This function runs the following vtysh command:

        ::

            # vrf attach {vrf_name}

        :param vrf_name: Mapping the port to vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vrf_attach(
        self, vrf_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unmapping port from vrf

        This function runs the following vtysh command:

        ::

            # no vrf attach {vrf_name}

        :param vrf_name: Unmapping the port from vrf.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vrf attach {vrf_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6}

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ipv6_address_secondary(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set secondary IPv6 address

        This function runs the following vtysh command:

        ::

            # ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ipv6 address {ipv6} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ipv6_address_secondary(
        self, ipv6,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IPv6 address

        This function runs the following vtysh command:

        ::

            # no ipv6 address {ipv6} secondary

        :param ipv6: X:X::X:X/M  Interface IPv6 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ipv6 address {ipv6} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable an interface.

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable an interface.

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def routing(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure interface as L3.

        This function runs the following vtysh command:

        ::

            # routing

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'routing'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_routing(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigure interface as L3.

        This function runs the following vtysh command:

        ::

            # no routing

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no routing'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_access(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Access configuration

        This function runs the following vtysh command:

        ::

            # vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan access {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_access(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove vlan access

        This function runs the following vtysh command:

        ::

            # no vlan access {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan access {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_allowed(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Allow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan trunk allowed {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_allowed(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disallow VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk allowed {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan trunk allowed {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native_tag(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native tag

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan trunk native tag'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native_tag(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove tag configuration on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native tag

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan trunk native tag'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def vlan_trunk_native(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'vlan trunk native {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_vlan_trunk_native(
        self, vlan_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove native VLAN on the trunk port

        This function runs the following vtysh command:

        ::

            # no vlan trunk native {vlan_id}

        :param vlan_id: <1-4094>  VLAN identifier
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no vlan trunk native {vlan_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_mode_passive(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets an interface as LACP passive.

        This function runs the following vtysh command:

        ::

            # lacp mode passive

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp mode passive'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_mode_passive(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets an LACP passive interface off.

        This function runs the following vtysh command:

        ::

            # no lacp mode passive

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lacp mode passive'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_mode_active(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets an interface as LACP active.

        This function runs the following vtysh command:

        ::

            # lacp mode active

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp mode active'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_mode_active(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets an LACP active interface off.

        This function runs the following vtysh command:

        ::

            # no lacp mode active

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lacp mode active'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_fallback(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable LACP fallback mode.

        This function runs the following vtysh command:

        ::

            # lacp fallback

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp fallback'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_fallback_mode_priority(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set fallback mode to priority.

        This function runs the following vtysh command:

        ::

            # lacp fallback mode priority

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp fallback mode priority'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_fallback_mode_all_active(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set fallback mode to all_active.

        This function runs the following vtysh command:

        ::

            # lacp fallback mode all_active

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp fallback mode all_active'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_fallback_mode_all_active(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set fallback mode to priority.

        This function runs the following vtysh command:

        ::

            # no lacp fallback mode all_active

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lacp fallback mode all_active'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_fallback_timeout(
        self, timeout,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set LACP fallback timeout.

        This function runs the following vtysh command:

        ::

            # lacp fallback timeout {timeout}

        :param timeout: <1-900>  LACP fallback timeout
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp fallback timeout {timeout}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_fallback_timeout(
        self, timeout,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set LACP fallback timeout to zero.

        This function runs the following vtysh command:

        ::

            # no lacp fallback timeout {timeout}

        :param timeout: <1-900>  LACP fallback timeout
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lacp fallback timeout {timeout}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def hash_l2_src_dst(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Base the hash on l2-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l2-src-dst

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'hash l2-src-dst'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def hash_l3_src_dst(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Base the hash on l3-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l3-src-dst

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'hash l3-src-dst'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def hash_l4_src_dst(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Base the hash on l4-src-dst.

        This function runs the following vtysh command:

        ::

            # hash l4-src-dst

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'hash l4-src-dst'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def lacp_rate_fast(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set LACP heartbeats are requested at the rate of one per second.

        This function runs the following vtysh command:

        ::

            # lacp rate fast

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'lacp rate fast'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_lacp_rate_fast(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set LACP heartbeats slow which is once every  30 seconds.

        This function runs the following vtysh command:

        ::

            # no lacp rate fast

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no lacp rate fast'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_qos_schedule_profile(
        self, schedule_profile_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply qos profiles on an interface.

        This function runs the following vtysh command:

        ::

            # apply qos schedule-profile {schedule_profile_name}

        :param schedule_profile_name: The schedule profile to apply.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'apply qos schedule-profile {schedule_profile_name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_apply_qos_schedule_profile(
        self, schedule_profile_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clears qos profiles from an interface.

        This function runs the following vtysh command:

        ::

            # no apply qos schedule-profile

        :param schedule_profile_name: The schedule profile to clear.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no apply qos schedule-profile'
        ]

        if schedule_profile_name:
            cmd.append(
                '{}{{schedule_profile_name}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_dscp(
        self, dscp_map_index,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the dscp override for the port.

        This function runs the following vtysh command:

        ::

            # qos dscp {dscp_map_index}

        :param dscp_map_index: The index into the dscp map.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos dscp {dscp_map_index}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_dscp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the dscp override for the port.

        This function runs the following vtysh command:

        ::

            # no qos dscp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos dscp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def qos_trust(
        self, value,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the qos trust mode for the port.

        This function runs the following vtysh command:

        ::

            # qos trust {value}

        :param value: The qos trust mode to set.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'qos trust {value}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_qos_trust(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the qos trust mode for the port.

        This function runs the following vtysh command:

        ::

            # no qos trust

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no qos trust'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_access_list_ip_in(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply ACL on interface to ingress traffic

        This function runs the following vtysh command:

        ::

            # apply access-list ip {acl_name} in

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'apply access-list ip {acl_name} in'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_apply_access_list_ip_in(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply no ACL on interface to ingress traffic

        This function runs the following vtysh command:

        ::

            # no apply access-list ip {acl_name} in

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no apply access-list ip {acl_name} in'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def apply_access_list_ip_out(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply ACL on interface to egress traffic

        This function runs the following vtysh command:

        ::

            # apply access-list ip {acl_name} out

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'apply access-list ip {acl_name} out'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_apply_access_list_ip_out(
        self, acl_name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Apply no ACL on interface to egress traffic

        This function runs the following vtysh command:

        ::

            # no apply access-list ip {acl_name} out

        :param acl_name: Access-list name
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no apply access-list ip {acl_name} out'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set IP address

        This function runs the following vtysh command:

        ::

            # ip static {ip}

        :param ip: Interface IP (ipv4 or ipv6) address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip static {ip}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_ip_static(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset IP address

        This function runs the following vtysh command:

        ::

            # no ip static {ip}

        :param ip: Interface IP (ipv4 or ipv6) address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no ip static {ip}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def default_gateway(
        self, gateway,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure the Default gateway address (IPv4 and IPv6)

        This function runs the following vtysh command:

        ::

            # default-gateway {gateway}

        :param gateway: IP (ipv4 or ipv6) address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'default-gateway {gateway}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_default_gateway(
        self, gateway,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove the Default gateway address (IPv4 and IPv6)

        This function runs the following vtysh command:

        ::

            # no default-gateway {gateway}

        :param gateway: IP (ipv4 or ipv6) address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no default-gateway {gateway}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def nameserver(
        self, primary_nameserver, secondary_nameserver='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure the nameserver

        This function runs the following vtysh command:

        ::

            # nameserver {primary_nameserver}

        :param primary_nameserver: Primary nameserver (ipv4 or ipv6) address.
        :param secondary_nameserver: Secondary nameserver (ipv4 or ipv6)
            address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_nameserver(
        self, primary_nameserver, secondary_nameserver='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configure the nameserver

        This function runs the following vtysh command:

        ::

            # no nameserver {primary_nameserver}

        :param primary_nameserver: Primary nameserver (ipv4 or ipv6) address.
        :param secondary_nameserver: Secondary nameserver (ipv4 or ipv6)
            address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def ip_dhcp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the mode as dhcp.

        This function runs the following vtysh command:

        ::

            # ip dhcp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'ip dhcp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Specifies the OSPF router-ID for a OSPF Router

        This function runs the following vtysh command:

        ::

            # router-id {id}

        :param id: <A.B.C.D> IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'router-id {id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_router_id(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        unconfigure router-ID for a OSPF Router

        This function runs the following vtysh command:

        ::

            # no router-id

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no router-id'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def redistribute_static(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Redistributes the static routes in router

        This function runs the following vtysh command:

        ::

            # redistribute static

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'redistribute static'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_redistribute_static(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes redistributed the static routes in router

        This function runs the following vtysh command:

        ::

            # no redistribute static

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no redistribute static'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def redistribute_connected(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Redistributes the connected routes in router

        This function runs the following vtysh command:

        ::

            # redistribute connected

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'redistribute connected'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_redistribute_connected(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes redistributed the connected routes in router

        This function runs the following vtysh command:

        ::

            # no redistribute connected

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no redistribute connected'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def redistribute_bgp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Redistributes the routes learned from BGP

        This function runs the following vtysh command:

        ::

            # redistribute bgp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'redistribute bgp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_redistribute_bgp(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes redistributed the routes learned from BGP

        This function runs the following vtysh command:

        ::

            # no redistribute bgp

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no redistribute bgp'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def default_information_originate_always(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Redistributes default routes in router

        This function runs the following vtysh command:

        ::

            # default-information originate always

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'default-information originate always'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_default_information_originate_always(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove redistributed default routes in router

        This function runs the following vtysh command:

        ::

            # no default-information originate always

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no default-information originate always'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_authentication_message_digest(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures MD5 authentication over area

        This function runs the following vtysh command:

        ::

            # area {area_id} authentication message-digest

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} authentication message-digest'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_authentication(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures text authentication over area

        This function runs the following vtysh command:

        ::

            # area {area_id} authentication

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} authentication'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_area_authentication(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes authentication over area

        This function runs the following vtysh command:

        ::

            # no area {area_id} authentication

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no area {area_id} authentication'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def max_metric_router_lsa(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the router as stub router

        This function runs the following vtysh command:

        ::

            # max-metric router-lsa

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'max-metric router-lsa'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def max_metric_router_lsa_on_startup(
        self, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures the router as stub router on startup

        This function runs the following vtysh command:

        ::

            # max-metric router-lsa on-startup {time}

        :param time: <5-86400> seconds
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'max-metric router-lsa on-startup {time}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_nssa(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures area as NSSA

        This function runs the following vtysh command:

        ::

            # area {area_id} nssa

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} nssa'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_nssa_no_summary(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures area as NSSA (Totally stubby)

        This function runs the following vtysh command:

        ::

            # area {area_id} nssa no-summary

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} nssa no-summary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_area_nssa_no_summary(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigures NSSA (Totally stubby) area

        This function runs the following vtysh command:

        ::

            # no area {area_id} nssa no-summary

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no area {area_id} nssa no-summary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_stub(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures area as stubby

        This function runs the following vtysh command:

        ::

            # area {area_id} stub

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} stub'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_area_stub(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigures stubby area

        This function runs the following vtysh command:

        ::

            # no area {area_id} stub

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no area {area_id} stub'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_stub_no_summary(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures area as Totally stubby

        This function runs the following vtysh command:

        ::

            # area {area_id} stub no-summary

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} stub no-summary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_area_stub_no_summary(
        self, area_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigures Totally stubby area

        This function runs the following vtysh command:

        ::

            # no area {area_id} stub no-summary

        :param area_id: <0-4294967295> area range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no area {area_id} stub no-summary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def distance_ospf_external(
        self, external_distance,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures distance for external routes

        This function runs the following vtysh command:

        ::

            # distance ospf external {external_distance}

        :param external_distance: <1-255> Distance for external routes
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'distance ospf external {external_distance}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_distance_ospf_external(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removing the distance for external routes

        This function runs the following vtysh command:

        ::

            # no distance ospf external

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no distance ospf external'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def network_area(
        self, network, area,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Adds the announcement network for OSPF

        This function runs the following vtysh command:

        ::

            # network {network} area {area}

        :param network: <A.B.C.D/M> IPv4 address with the prefix len
        :param area: <0-4228250625 | A.B.C.D> Area-id range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'network {network} area {area}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link(
        self, area_id, router_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring virtual links between OSPF switches

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id}

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} virtual-link {router_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_area_virtual_link(
        self, area_id, router_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disabling virtual links between OSPF switches

        This function runs the following vtysh command:

        ::

            # no area {area_id} virtual-link {router_id}

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no area {area_id} virtual-link {router_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link_authentication_message_digest(
        self, area_id, router_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring virtual links with authenication

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id} authentication message-digest # noqa

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'area {area_id} virtual-link {router_id} authentication message-digest'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link_hello_interval(
        self, area_id, router_id, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring hello-interval for virtual links

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id} hello-interval {time}

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param time: <1-65535>  Seconds
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} virtual-link {router_id} hello-interval {time}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link_retransmit_interval(
        self, area_id, router_id, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring retransmit-interval for virtual-links

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id} retransmit-interval {time} # noqa

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param time: <1-65535>  Seconds
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} virtual-link {router_id} retransmit-interval {time}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link_transmit_delay(
        self, area_id, router_id, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring transmit-delay for virtual links

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id} transmit-delay {time}

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param time: <1-65535>  Seconds
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} virtual-link {router_id} transmit-delay {time}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link_dead_interval(
        self, area_id, router_id, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring dead-interval for virtual links

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id} dead-interval {time}

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param time: <1-65535>  Seconds
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'area {area_id} virtual-link {router_id} dead-interval {time}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def area_virtual_link_message_digest_key_md5(
        self, area_id, router_id, key, password,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configuring virtual links with md5 authentication

        This function runs the following vtysh command:

        ::

            # area {area_id} virtual-link {router_id} message-digest-key {key} md5 {password} # noqa

        :param area_id: <0-4228250625 | A.B.C.D> Area-id range
        :param router_id: <A.B.C.D> Router ID of the remote ABR
        :param key: <1-255>  Key ID
        :param password: MD5_KEY  The OSPF password (key)
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """  # noqa

        cmd = [
            'area {area_id} virtual-link {router_id} message-digest-key {key} md5 {password}'  # noqa
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_network_area(
        self, network, area,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the announcement network for OSPF

        This function runs the following vtysh command:

        ::

            # no network {network} area {area}

        :param network: <A.B.C.D/M> IPv4 address with the prefix length
        :param area: <0-4228250625 | A.B.C.D> Area-id range
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no network {network} area {area}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Specifies the BGP router-ID for a BGP Router

        This function runs the following vtysh command:

        ::

            # bgp router-id {id}

        :param id: <A.B.C.D> IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'bgp router-id {id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_bgp_router_id(
        self, id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the BGP router-ID for a BGP Router

        This function runs the following vtysh command:

        ::

            # no bgp router-id {id}

        :param id: <A.B.C.D> IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no bgp router-id {id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def bgp_fast_external_failover(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Immediately reset session if a link to a directly connected external
        peer goes down

        This function runs the following vtysh command:

        ::

            # bgp fast-external-failover

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'bgp fast-external-failover'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_bgp_fast_external_failover(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disables BGP fast external failover

        This function runs the following vtysh command:

        ::

            # no bgp fast-external-failover

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no bgp fast-external-failover'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def network(
        self, network,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Adds the announcement network for BGP

        This function runs the following vtysh command:

        ::

            # network {network}

        :param network: <A.B.C.D/M> IPv4 address with the prefix len
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'network {network}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_network(
        self, network,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the announcement network for BGP

        This function runs the following vtysh command:

        ::

            # no network {network}

        :param network: <A.B.C.D/M> IPv4 address with the prefix length
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no network {network}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def maximum_paths(
        self, num,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the maximum number of paths for a BGP route

        This function runs the following vtysh command:

        ::

            # maximum-paths {num}

        :param num: <1-255> Maximum number of paths. Default is 1
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'maximum-paths {num}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_maximum_paths(
        self, num,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the max number of paths to the default value of 1

        This function runs the following vtysh command:

        ::

            # no maximum-paths {num}

        :param num: <1-255> Maximum number of paths. Default is 1
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no maximum-paths {num}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def timers_bgp(
        self, keepalive, hold,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the keepalive interval and hold time for a BGP router

        This function runs the following vtysh command:

        ::

            # timers bgp {keepalive} {hold}

        :param keepalive: <0-65535> Keepalive interval in seconds. Default is
            60
        :param hold: <0 - 65535> Hold time in seconds. Default is 180
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'timers bgp {keepalive} {hold}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_timers_bgp(
        self, keepalive='', hold='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the default values for keepalive interval and hold time for a BGP
        router

        This function runs the following vtysh command:

        ::

            # no timers bgp

        :param keepalive: <0 - 65535> Keepalive interval in seconds. Default
            is 60
        :param hold: <0 - 65535> Hold time in seconds. Default is 180
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_remote_as(
        self, ip, asn,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures a BGP neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {ip} remote-as {asn}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param asn: <1 - 4294967295> Neighbor AS number. Ranges from 1 to
            4294967295
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} remote-as {asn}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {ip}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_route_map(
        self, ip, route_name, action,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} route-map {route_name} {action}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_route_map(
        self, ip, route_name, action,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {ip} route-map {route_name} {action}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_prefix_list(
        self, peer, prefix_name, filter_direction='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_prefix_list(
        self, peer, prefix_name, filter_direction='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove a prefix-list filter from the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {peer} prefix-list {prefix_name}

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param prefix_name: <WORD> The name of a prefix list
        :param filter_direction: <in|out> Filters incoming/outgoing routes
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_description(
        self, ip, text,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {ip} description {text}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param text: Description of the peer router. String of maximum length
            80 chars
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} description {text}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_description(
        self, ip, text='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes a BGP neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} description

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param text: Description of the peer router.String of maximum length
            80 chars
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_password(
        self, ip, pwd,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enables MD5 authentication on a TCP connection between BGP peers.

        This function runs the following vtysh command:

        ::

            # neighbor {ip} password {pwd}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param pwd: Password in plain text.String of maximum length 80 chars
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} password {pwd}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_password(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes MD5 authentication on a TCP connection between BGP peers.

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} password

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {ip} password'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_timers(
        self, ip, keepalive, hold,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets the keepalive interval and hold time for a specific BGP peer

        This function runs the following vtysh command:

        ::

            # neighbor {ip} timers {keepalive} {hold}

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param keepalive: <0 - 65535> Keepalive interval in seconds.Default is
            60
        :param hold: <0-65535> Hold time in seconds. Default is 180
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} timers {keepalive} {hold}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_timers(
        self, ip, keepalive='', hold='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_allowas_in(
        self, ip, val='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Specifies an allow-as-in occurrence number for an AS to be in the AS
        path

        This function runs the following vtysh command:

        ::

            # neighbor {ip} allowas-in

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param val: <0 - 10> Number of times BGP can allow an instance of AS
            to be in the AS_PATH
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_allowas_in(
        self, ip, val='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clears the allow-as-in occurrence number for an AS to be in the AS path

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} allowas-in

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param val: <0 - 10> Number of times BGP can allow aninstance of AS to
            be in the AS_PATH
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_remove_private_as(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes private AS numbers from the AS pathin outbound routing updates

        This function runs the following vtysh command:

        ::

            # neighbor {ip} remove-private-AS

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} remove-private-AS'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_remove_private_as(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Resets to a cleared state (default)

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} remove-private-AS

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {ip} remove-private-AS'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_soft_reconfiguration_inbound(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enables software-based reconfiguration to generate updates from a
        neighbor without clearing the BGP session

        This function runs the following vtysh command:

        ::

            # neighbor {ip} soft-reconfiguration inbound

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} soft-reconfiguration inbound'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_soft_reconfiguration_inbound(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Resets to a cleared state (default)

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} soft-reconfiguration inbound

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {ip} soft-reconfiguration inbound'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_shutdown(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Shuts down the neighbor. This disables the peer routerbut preserves
        neighbor configuration

        This function runs the following vtysh command:

        ::

            # neighbor {ip} shutdown

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {ip} shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_shutdown(
        self, ip,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Re-enables the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {ip} shutdown

        :param ip: <A.B.C.D> Neighbor IPv4 address
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {ip} shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_peer_group(
        self, ip_or_group, group='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Assigns a neighbor to a peer-group

        This function runs the following vtysh command:

        ::

            # neighbor {ip_or_group} peer-group

        :param ip_or_group: <A.B.C.D> Neighbor IPv4 address<X:X::X:X> Neighbor
            IPv6 address<WORD> Neighbor group
        :param group: ('Peer-group name.String of maximum length 80 chars',)
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def neighbor_update_source(
        self, peer, update_source,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Applies an update source to the neighbor

        This function runs the following vtysh command:

        ::

            # neighbor {peer} update-source {update_source}

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param update_source: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address
            or neighbor tag
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'neighbor {peer} update-source {update_source}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_update_source(
        self, peer,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove a an update source to the neighbor

        This function runs the following vtysh command:

        ::

            # no neighbor {peer} update-source

        :param peer: <A.B.C.D|X:X::X:X|WORD> peer IPv4/IPv6 address or
            neighbor tag
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no neighbor {peer} update-source'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_neighbor_peer_group(
        self, ip_or_group, group='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes the neighbor from the peer-group

        This function runs the following vtysh command:

        ::

            # no neighbor {ip_or_group} peer-group

        :param ip_or_group: <A.B.C.D> Neighbor IPv4 address<X:X::X:X> Neighbor
            IPv6 address<WORD> Neighbor group
        :param group: Peer-group name. String of maximum length 80 chars
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def redistribute(
        self, type,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Configures route redistribution of the specified protocol into BGP

        This function runs the following vtysh command:

        ::

            # redistribute {type}

        :param type: <connected | static | ospf>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'redistribute {type}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_redistribute(
        self, type,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unconfigures route redistribution of the specified protocol into BGP

        This function runs the following vtysh command:

        ::

            # no redistribute {type}

        :param type: <connected | static | ospf>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no redistribute {type}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable the VLAN.

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable the VLAN.

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def description(
        self, description,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VLAN description

        This function runs the following vtysh command:

        ::

            # description {description}

        :param description: VLAN description.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'description {description}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_description(
        self, description,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-set VLAN description

        This function runs the following vtysh command:

        ::

            # no description {description}

        :param description: VLAN description.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no description {description}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable tftp server.

        This function runs the following vtysh command:

        ::

            # enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_enable`
        """

        cmd = [
            'enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_tftp_server_enable(result)

    def no_enable(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable tftp server.

        This function runs the following vtysh command:

        ::

            # no enable

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_no_enable`
        """

        cmd = [
            'no enable'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_tftp_server_no_enable(result)

    def path(
        self, path,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set Path of tftp-server

        This function runs the following vtysh command:

        ::

            # path {path}

        :param path: path of the directory
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_path`
        """

        cmd = [
            'path {path}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_tftp_server_path(result)

    def no_path(
        self, path,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset path to tftp server.

        This function runs the following vtysh command:

        ::

            # no path {path}

        :param path: path of the directory
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_no_path`
        """

        cmd = [
            'no path {path}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_tftp_server_no_path(result)

    def secure_mode(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable secure mode for tftp server.

        This function runs the following vtysh command:

        ::

            # secure-mode

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_secure_mode`
        """

        cmd = [
            'secure-mode'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_tftp_server_secure_mode(result)

    def no_secure_mode(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable secure mode for tftp server.

        This function runs the following vtysh command:

        ::

            # no secure-mode

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_tftp_server_no_secure_mode`
        """

        cmd = [
            'no secure-mode'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_tftp_server_no_secure_mode(result)


class ConfigDhcpServer(ContextManager):
    """
    DHCP server configuration.

    pre_commands:

    ::

        ['config terminal', 'dhcp-server']

    post_commands:

    ::

        ['end']
    """  # noqa
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
        prefix_len_value='', lease_duration_value='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets DHCP dynamic configuration.

        This function runs the following vtysh command:

        ::

            # range {range_name} start-ip-address {start_ip} end-ip-address {end_ip} # noqa

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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_range_start_ip_address_end_ip_address(
        self, range_name, start_ip, end_ip, subnet_mask='',
        broadcast_address='', tag_name='', set_name='',
        prefix_len_value='', lease_duration_value='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes DHCP dynamic configuration.

        This function runs the following vtysh command:

        ::

            # no range {range_name} start-ip-address {start_ip} end-ip-address {end_ip}  # noqa

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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def static(
        self, ip_address, mac_address='', hostname='',
        client_id='', set_tag_names='', lease_duration_value='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_static(
        self, ip_address, mac_address='', hostname='',
        client_id='', set_tag_names='', lease_duration_value='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def option_set(
        self, option_name='', option_number='', option_value='',
        tag_name='', ipv6='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets DHCP configuration values using an option name.

        This function runs the following vtysh command:

        ::

            # option set

        :param option_name: DHCP option name
        :param option_number: DHCP option number
        :param option_value: DHCP option value
        :param tag_name: Match tags list. Each tag length must be less than 15
            chars.
        :param ipv6: Enable ipv6 for the set.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'option set'
        ]

        if option_name:
            cmd.append(
                '{}{{option_name}}{}'.format(
                    ' option-name ', ''
                )
            )

        if option_number:
            cmd.append(
                '{}{{option_number}}{}'.format(
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_option_set(
        self, option_name='', option_number='', option_value='',
        tag_name='', ipv6='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes DHCP configuration values using an option name.

        This function runs the following vtysh command:

        ::

            # no option set

        :param option_name: DHCP option name
        :param option_number: DHCP option number
        :param option_value: DHCP option value
        :param tag_name: Match tags list. Each tag length must be less than 15
            chars.
        :param ipv6: Enable ipv6 for the set.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no option set'
        ]

        if option_name:
            cmd.append(
                '{}{{option_name}}{}'.format(
                    ' option-name ', ''
                )
            )

        if option_number:
            cmd.append(
                '{}{{option_number}}{}'.format(
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def match_set_tag(
        self, tag_name, option_number='', option_name='',
        option_value='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_match_set_tag(
        self, tag_name, option_name='', option_number='',
        option_value='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
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
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def boot_set_file(
        self, file_name, tag_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Sets DHCP bootp options.

        This function runs the following vtysh command:

        ::

            # boot set file {file_name}

        :param file_name: DHCP boot file name
        :param tag_name: DHCP match tag name. Length must be less than 15
            chars.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_boot_set_file(
        self, file_name, tag_name='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Removes bootp options.

        This function runs the following vtysh command:

        ::

            # no boot set file {file_name}

        :param file_name: DHCP boot file name
        :param tag_name: DHCP match tag name. Length must be less than 15
            chars.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
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

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
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
    """  # noqa
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
        self, portlbl,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set the destination interface.

        This function runs the following vtysh command:

        ::

            # destination interface {port}

        :param portlbl: Label that identifies an interface or LAG
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'destination interface {port}'
        ]

        port = self.enode.ports.get(portlbl, portlbl)

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_destination_interface(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Un-set the destination interface and shutdown the session.

        This function runs the following vtysh command:

        ::

            # no destination interface

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.parse_config_mirror_session_no_destination_interface`
        """

        cmd = [
            'no destination interface'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        return parse_config_mirror_session_no_destination_interface(result)

    def shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Shutdown the mirroring session.

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Activate the mirroring session.

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def source_interface(
        self, portlbl, direction,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Assign a source interface.

        This function runs the following vtysh command:

        ::

            # source interface {port} {direction}

        :param portlbl: Label that identifies an interface or LAG
        :param direction: <both | rx | tx>
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'source interface {port} {direction}'
        ]

        port = self.enode.ports.get(portlbl, portlbl)

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_source_interface(
        self, portlbl,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove a source interface from the session.

        This function runs the following vtysh command:

        ::

            # no source interface {port}

        :param portlbl: Ethernet interface or LAG
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no source interface {port}'
        ]

        port = self.enode.ports.get(portlbl, portlbl)

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)


class ConfigQueueProfile(ContextManager):
    """
    Configure a queue profile.

    pre_commands:

    ::

        ['config terminal', 'qos queue-profile {name}']

    post_commands:

    ::

        ['end']
    """  # noqa
    def __init__(self, enode, name):
        self.enode = enode
        self.name = name

    def __enter__(self):
        commands = """\
            config terminal
            qos queue-profile {name}
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

    def map_queue_local_priority(
        self, queue, local_priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Map a local priority to a queue.

        This function runs the following vtysh command:

        ::

            # map queue {queue} local-priority {local_priority}

        :param queue: The queue to configure.
        :param local_priority: The local priority to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'map queue {queue} local-priority {local_priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_map_queue(
        self, queue,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clear the map for a queue.

        This function runs the following vtysh command:

        ::

            # no map queue {queue}

        :param queue: The queue to clear.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no map queue {queue}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_map_queue_local_priority(
        self, queue, local_priority,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clear a local priority from a queue.

        This function runs the following vtysh command:

        ::

            # no map queue {queue} local-priority {local_priority}

        :param queue: The queue to configure.
        :param local_priority: The local priority to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no map queue {queue} local-priority {local_priority}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def name_queue(
        self, queue, name,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Name a queue.

        This function runs the following vtysh command:

        ::

            # name queue {queue} {name}

        :param queue: The queue to configure.
        :param name: The name to assign to the queue.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'name queue {queue} {name}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_name_queue(
        self, queue,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clears the name of a queue.

        This function runs the following vtysh command:

        ::

            # no name queue {queue}

        :param queue: The queue to clear.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no name queue {queue}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)


class ConfigScheduleProfile(ContextManager):
    """
    Configure a schedule profile.

    pre_commands:

    ::

        ['config terminal', 'qos schedule-profile {name}']

    post_commands:

    ::

        ['end']
    """  # noqa
    def __init__(self, enode, name):
        self.enode = enode
        self.name = name

    def __enter__(self):
        commands = """\
            config terminal
            qos schedule-profile {name}
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

    def strict_queue(
        self, queue,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Assign the strict algorithm to a queue.

        This function runs the following vtysh command:

        ::

            # strict queue {queue}

        :param queue: The queue to configure.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'strict queue {queue}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_strict_queue(
        self, queue,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clear the strict algorithm from a queue.

        This function runs the following vtysh command:

        ::

            # no strict queue {queue}

        :param queue: The queue to clear.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no strict queue {queue}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def dwrr_queue_weight(
        self, queue, weight,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Assign the dwrr algorithm to a queue.

        This function runs the following vtysh command:

        ::

            # dwrr queue {queue} weight {weight}

        :param queue: The queue to configure.
        :param weight: The weight for the queue.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'dwrr queue {queue} weight {weight}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_dwrr_queue(
        self, queue,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Clears the dwrr algorithm for a queue.

        This function runs the following vtysh command:

        ::

            # no dwrr queue {queue}

        :param queue: The queue to clear.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no dwrr queue {queue}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)


class ConfigAccessListIpTestname(ContextManager):
    """
    ACE permission.

    pre_commands:

    ::

        ['config terminal', 'access-list ip {acl_name}']

    post_commands:

    ::

        ['end']
    """  # noqa
    def __init__(self, enode, acl_name):
        self.enode = enode
        self.acl_name = acl_name

    def __enter__(self):
        commands = """\
            config terminal
            access-list ip {acl_name}
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

    def permit(
        self, negate, sequence, protocol, ip1, port1, ip2,
        port2, count='', log='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Permit access-list entry

        This function runs the following vtysh command:

        ::

            # {negate} {sequence} permit {protocol} {ip1} {port1} {ip2} {port2}

        :param negate: remove access-list entry.
        :param sequence: sequence number of ACE.
        :param protocol: Protocol (number) type.
        :param ip1: <A.B.C.D/M> Source IPv4 address.
        :param port1: Source Port range <1-65535>.
        :param ip2: <A.B.C.D/M> Destination IPv4 address.
        :param port2: Destination Port range <1-65535>.
        :param count: count the packets that match this entry.
        :param log: log and count the packets that match this entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            '{negate} {sequence} permit {protocol} {ip1} {port1} {ip2} {port2}'
        ]

        if count:
            cmd.append(
                '{}{{count}}{}'.format(
                    '', ''
                )
            )

        if log:
            cmd.append(
                '{}{{log}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def deny(
        self, negate, sequence, protocol, ip1, port1, ip2,
        port2, count='', log='',
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Deny access-list entry

        This function runs the following vtysh command:

        ::

            # {negate} {sequence} deny {protocol} {ip1} {port1} {ip2} {port2}

        :param negate: remove access-list entry.
        :param sequence: sequence number of ACE.
        :param protocol: Protocol type for entry.
        :param ip1: <A.B.C.D/M> Source IPv4 address.
        :param port1: Source Port range <1-65535>.
        :param ip2: <A.B.C.D/M> Destination IPv4 address.
        :param port2: Destination Port range <1-65535>.
        :param count: count the packets that match this entry.
        :param log: log and count the packets that match this entry.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            '{negate} {sequence} deny {protocol} {ip1} {port1} {ip2} {port2}'
        ]

        if count:
            cmd.append(
                '{}{{count}}{}'.format(
                    '', ''
                )
            )

        if log:
            cmd.append(
                '{}{{log}}{}'.format(
                    '', ''
                )
            )

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no(
        self, sequence,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove access-list entry

        This function runs the following vtysh command:

        ::

            # no {sequence}

        :param sequence: sequence number of ACE.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no {sequence}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)


class ConfigVrrpInterface(ContextManager):
    """
    VRRP-Interface configuration.

    pre_commands:

    ::

        ['config terminal', 'interface {port}', 'vrrp {grpid} address-family {af}']

    post_commands:

    ::

        ['exit', 'end']
    """  # noqa
    def __init__(self, enode, portlbl, grpid, af):
        self.enode = enode
        self.port = enode.ports.get(portlbl, portlbl)
        self.grpid = grpid
        self.af = af

    def __enter__(self):
        commands = """\
            config terminal
            interface {port}
            vrrp {grpid} address-family {af}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
            exit
            end
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

    def address_primary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VRRP primary IP address

        This function runs the following vtysh command:

        ::

            # address {ipv4} primary

        :param ipv4: A.B.C.D VRRP primary virtual IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'address {ipv4} primary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_address_primary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset VRRP primary IP address

        This function runs the following vtysh command:

        ::

            # no address {ipv4} primary

        :param ipv4: A.B.C.D VRRP primary virtual IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no address {ipv4} primary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VRRP secondary IP address

        This function runs the following vtysh command:

        ::

            # address {ipv4} secondary

        :param ipv4: A.B.C.D VRRP secondary virtual IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_address_secondary(
        self, ipv4,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset VRRP secondary IP address

        This function runs the following vtysh command:

        ::

            # no address {ipv4} secondary

        :param ipv4: A.B.C.D VRRP secondary virtual IP address.
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no address {ipv4} secondary'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def priority(
        self, prio,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VRRP virtual router priority

        This function runs the following vtysh command:

        ::

            # priority {prio}

        :param prio: [0-255] VRRP virtual router Priority Level
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'priority {prio}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_priority(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset VRRP virtual router priority

        This function runs the following vtysh command:

        ::

            # no priority

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no priority'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def version(
        self, ver,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VRRP virtual router version

        This function runs the following vtysh command:

        ::

            # version {ver}

        :param ver: [2-3] VRRP virtual router version
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'version {ver}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_version(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset VRRP virtual router version

        This function runs the following vtysh command:

        ::

            # no version

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no version'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def preempt(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set VRRP virtual router preempt mode

        This function runs the following vtysh command:

        ::

            # preempt

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'preempt'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_preempt(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Unset VRRP virtual router preempt mode

        This function runs the following vtysh command:

        ::

            # no preempt

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no preempt'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Enable VRRP VR

        This function runs the following vtysh command:

        ::

            # shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_shutdown(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Disable VRRP VR

        This function runs the following vtysh command:

        ::

            # no shutdown

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no shutdown'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def preempt_delay_minimum(
        self, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set minimum preempt delay time

        This function runs the following vtysh command:

        ::

            # preempt delay minimum {time}

        :param time: [0-3600] VRRP VR minimum preempt delay time
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'preempt delay minimum {time}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_preempt_delay(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Reset minimum preempt delay time

        This function runs the following vtysh command:

        ::

            # no preempt delay

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no preempt delay'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def timers_advertise(
        self, time,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set minimum VRRP advertise time

        This function runs the following vtysh command:

        ::

            # timers advertise {time}

        :param time: [100-40950] VRRP VR advertise time
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'timers advertise {time}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_timers_advertise(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Reset minimum VRRP advertise time

        This function runs the following vtysh command:

        ::

            # no timers advertise

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no timers advertise'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def track(
        self, track_id,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Set track object

        This function runs the following vtysh command:

        ::

            # track {track_id}

        :param track_id: [1-500] VRRP tracking entity
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'track {track_id}'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)

    def no_track(
        self,
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        Remove track object

        This function runs the following vtysh command:

        ::

            # no track

        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        """

        cmd = [
            'no track'
        ]

        shell = self.enode.get_shell(_shell)

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )

        if result:
            raise determine_exception(result)(result)


def show_interface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Interface infomation.

    This function runs the following vtysh command:

    ::

        # show interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface`
    """

    cmd = [
        'show interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface(result)


def show_interface_brief(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show all interfaces

    This function runs the following vtysh command:

    ::

        # show interface brief

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_brief`
    """

    cmd = [
        'show interface brief'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_brief(result)


def show_interface_mgmt(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Managment Interface infomation.

    This function runs the following vtysh command:

    ::

        # show interface mgmt

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_mgmt`
    """

    cmd = [
        'show interface mgmt'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_mgmt(result)


def show_interface_subinterface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show subinterfaces configured on this interface

    This function runs the following vtysh command:

    ::

        # show interface {port} subinterface

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_subinterface`
    """

    cmd = [
        'show interface {port} subinterface'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_subinterface(result)


def show_interface_subinterface_brief(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show subinterface summary on a physical port

    This function runs the following vtysh command:

    ::

        # show interface {port} subinterface brief

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_subinterface_brief`
    """

    cmd = [
        'show interface {port} subinterface brief'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_subinterface_brief(result)


def show_interface_queues(
    enode, portlbl='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show queue statistics for this interface

    This function runs the following vtysh command:

    ::

        # show interface {port} queues

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_queues`
    """

    cmd = [
        'show interface {port} queues'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_queues(result)


def show_vlan(
    enode, vlanid='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show VLAN configuration.

    This function runs the following vtysh command:

    ::

        # show vlan

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param vlanid: Vlan ID number.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlan(result)


def show_lacp_interface(
    enode, portlbl='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show LACP interface.

    This function runs the following vtysh command:

    ::

        # show lacp interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_interface`
    """

    cmd = [
        'show lacp interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_lacp_interface(result)


def show_lacp_aggregates(
    enode, lag='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show LACP aggregates.

    This function runs the following vtysh command:

    ::

        # show lacp aggregates

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param lag: Link-aggregate name.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_lacp_aggregates(result)


def show_lacp_configuration(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show LACP configuration.

    This function runs the following vtysh command:

    ::

        # show lacp configuration

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lacp_configuration`
    """

    cmd = [
        'show lacp configuration'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_lacp_configuration(result)


def show_lldp_neighbor_info(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show global LLDP neighbor information.

    This function runs the following vtysh command:

    ::

        # show lldp neighbor-info {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lldp_neighbor_info`
    """

    cmd = [
        'show lldp neighbor-info {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_lldp_neighbor_info(result)


def show_lldp_statistics(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show LLDP statistics.

    This function runs the following vtysh command:

    ::

        # show lldp statistics

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_lldp_statistics`
    """

    cmd = [
        'show lldp statistics'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_lldp_statistics(result)


def show_sftp_server(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show sftp server configuration.

    This function runs the following vtysh command:

    ::

        # show sftp server

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_sftp_server`
    """

    cmd = [
        'show sftp server'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_sftp_server(result)


def show_ip_interface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ip interface information.

    This function runs the following vtysh command:

    ::

        # show ip interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_interface`
    """

    cmd = [
        'show ip interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_interface(result)


def show_ipv6_interface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ipv6 interface information.

    This function runs the following vtysh command:

    ::

        # show ipv6 interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_interface`
    """

    cmd = [
        'show ipv6 interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ipv6_interface(result)


def show_ip_bgp_summary(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show bgp neighbors information summary.

    This function runs the following vtysh command:

    ::

        # show ip bgp summary

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_summary`
    """

    cmd = [
        'show ip bgp summary'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_bgp_summary(result)


def show_ip_bgp_neighbors(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show bgp neighbors information.

    This function runs the following vtysh command:

    ::

        # show ip bgp neighbors

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_neighbors`
    """

    cmd = [
        'show ip bgp neighbors'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_bgp_neighbors(result)


def show_ip_bgp(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show bgp routing information.

    This function runs the following vtysh command:

    ::

        # show ip bgp

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp`
    """

    cmd = [
        'show ip bgp'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_bgp(result)


def show_ipv6_bgp(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show bgp routing information.

    This function runs the following vtysh command:

    ::

        # show ipv6 bgp

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_bgp`
    """

    cmd = [
        'show ipv6 bgp'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ipv6_bgp(result)


def show_ip_ospf_neighbor_detail(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ospf neighbor detail information.

    This function runs the following vtysh command:

    ::

        # show ip ospf neighbor detail

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_neighbor_detail`
    """

    cmd = [
        'show ip ospf neighbor detail'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_ospf_neighbor_detail(result)


def show_ip_ospf_neighbor(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ospf neighbor information.

    This function runs the following vtysh command:

    ::

        # show ip ospf neighbor

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_neighbor`
    """

    cmd = [
        'show ip ospf neighbor'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_ospf_neighbor(result)


def show_ip_ospf_interface(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ospf interface detail.

    This function runs the following vtysh command:

    ::

        # show ip ospf interface

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_interface`
    """

    cmd = [
        'show ip ospf interface'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_ospf_interface(result)


def show_ip_ospf(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ospf detail.

    This function runs the following vtysh command:

    ::

        # show ip ospf

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf`
    """

    cmd = [
        'show ip ospf'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_ospf(result)


def show_ip_ospf_route(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ospf detail.

    This function runs the following vtysh command:

    ::

        # show ip ospf route

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ospf_route`
    """

    cmd = [
        'show ip ospf route'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_ospf_route(result)


def show_running_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show running-config information.

    This function runs the following vtysh command:

    ::

        # show running-config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_running_config`
    """

    cmd = [
        'show running-config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_running_config(result)


def show_running_config_interface(
    enode, portlbl='', subint='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show running-config for the interface.

    This function runs the following vtysh command:

    ::

        # show running-config interface {port} {subint}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param subint: Subinterface ID
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_running_config_interface`
    """

    cmd = [
        'show running-config interface {port} {subint}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    if subint:
        cmd.append(
            '{}{{subint}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_running_config_interface(result)


def show_ip_route(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show Routing Table.

    This function runs the following vtysh command:

    ::

        # show ip route

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_route`
    """

    cmd = [
        'show ip route'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_route(result)


def show_ipv6_route(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display the routing table.

    This function runs the following vtysh command:

    ::

        # show ipv6 route

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_route`
    """

    cmd = [
        'show ipv6 route'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ipv6_route(result)


def show_sflow(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show sFlow information.

    This function runs the following vtysh command:

    ::

        # show sflow

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_sflow`
    """

    cmd = [
        'show sflow'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_sflow(result)


def show_sflow_interface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show sFlow information for the interface.

    This function runs the following vtysh command:

    ::

        # show sflow interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_sflow_interface`
    """

    cmd = [
        'show sflow interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_sflow_interface(result)


def show_udld_interface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show UDLD information for the interface.

    This function runs the following vtysh command:

    ::

        # show udld interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_udld_interface`
    """

    cmd = [
        'show udld interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_udld_interface(result)


def show_rib(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show Routing Information Base.

    This function runs the following vtysh command:

    ::

        # show rib

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_rib`
    """

    cmd = [
        'show rib'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_rib(result)


def show_ip_ecmp(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show ECMP Configuration

    This function runs the following vtysh command:

    ::

        # show ip ecmp

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_ecmp`
    """

    cmd = [
        'show ip ecmp'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_ecmp(result)


def show_version(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show version information.

    This function runs the following vtysh command:

    ::

        # show version

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_version`
    """

    cmd = [
        'show version'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_version(result)


def show_arp(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show arp table.

    This function runs the following vtysh command:

    ::

        # show arp

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_arp`
    """

    cmd = [
        'show arp'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_arp(result)


def clear_bgp(
    enode, peer, softreconfig,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Clear bgp peer.

    This function runs the following vtysh command:

    ::

        # clear bgp {peer} {softreconfig}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param peer: BGP peer to clear.
    :param softreconfig: <in | out | soft>
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    """

    cmd = [
        'clear bgp {peer} {softreconfig}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    if result:
        raise determine_exception(result)(result)


def clear_udld_statistics(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Clear UDLD statistics from all interfaces.

    This function runs the following vtysh command:

    ::

        # clear udld statistics

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    """

    cmd = [
        'clear udld statistics'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    if result:
        raise determine_exception(result)(result)


def clear_udld_statistics_interface(
    enode, portlbl,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Clear UDLD statistics for the interface.

    This function runs the following vtysh command:

    ::

        # clear udld statistics interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param portlbl: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    """

    cmd = [
        'clear udld statistics interface {port}'
    ]

    port = enode.ports.get(portlbl, portlbl)

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    if result:
        raise determine_exception(result)(result)


def clear_access_list_hitcounts_all(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Clear all ACL stat values.

    This function runs the following vtysh command:

    ::

        # clear access-list hitcounts all

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    """

    cmd = [
        'clear access-list hitcounts all'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    if result:
        raise determine_exception(result)(result)


def clear_access_list_hitcounts_ip_interface(
    enode, acl_name, port,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Clear ACL state values per port.

    This function runs the following vtysh command:

    ::

        # clear access-list hitcounts ip {acl_name} interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param acl_name: Access-list name.
    :param port: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    """

    cmd = [
        'clear access-list hitcounts ip {acl_name} interface {port}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    if result:
        raise determine_exception(result)(result)


def ping_repetitions(
    enode, destination, count,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Send IPv4 ping

    This function runs the following vtysh command:

    ::

        # ping {destination} repetitions {count}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param destination: <A.B.C.D> IPv4 address.
    :param count: Number of packets to send.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping_repetitions`
    """

    cmd = [
        'ping {destination} repetitions {count}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_ping_repetitions(result)


def ping6_repetitions(
    enode, destination, count,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Send IPv6 ping

    This function runs the following vtysh command:

    ::

        # ping6 {destination} repetitions {count}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param destination: <X:X::X:X> IPv6 address.
    :param count: Number of packets to send.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_ping6_repetitions`
    """

    cmd = [
        'ping6 {destination} repetitions {count}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_ping6_repetitions(result)


def ping(
    enode, destination, count='', size='', data='', interval='',
    timeout='', tos='', vrf='', ip_option='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Send IPv4 ping

    This function runs the following vtysh command:

    ::

        # ping {destination}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param destination: <A.B.C.D> IPv4 address.
    :param count: Number of packets to send.
    :param size: Size of packets to send.
    :param data: Data to be filled in each packet.
    :param interval: Time interval between ping requests.
    :param timeout: Max time to wait for ping reply.
    :param tos: Type of service to be placed in each probe.
    :param vrf: Type of service to be placed in each probe.
    :param ip_option: Ip-option.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    if vrf:
        cmd.append(
            '{}{{vrf}}{}'.format(
                'vrf ', ''
            )
        )

    if ip_option:
        cmd.append(
            '{}{{ip_option}}{}'.format(
                'ip-option ', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_ping(result)


def ping6(
    enode, destination, count='', size='', data='', interval='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Send IPv6 ping

    This function runs the following vtysh command:

    ::

        # ping6 {destination}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param destination: <X:X::X:X> IPv6 address.
    :param count: Number of packets to send.
    :param size: Size of packets to send.
    :param data: Data to be filled in each packet.
    :param interval: Time interval between ping requests.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_ping6(result)


def copy_core_dump(
    enode, daemonname, instance_id='', transport='', username='',
    serveraddress='', filename='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Copy Coredump to Server

    This function runs the following vtysh command:

    ::

        # copy core-dump {daemonname}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param daemonname: Name of the daemon name or kernel [Mandatory]
    :param instance_id: instance_id ONLY for daemon,NOT FOR Kernel
    :param transport: method for transport coredump [Mandatory]
    :param username: username of server,ONLY for sftp,NOT FOR TFTP
    :param serveraddress: IP address <A.B.C.D> of server [Mandatory]
    :param filename: name of core filei [Optional]
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_copy_core_dump`
    """

    cmd = [
        'copy core-dump {daemonname}'
    ]

    if instance_id:
        cmd.append(
            '{}{{instance_id}}{}'.format(
                'instance-id ', ''
            )
        )

    if transport:
        cmd.append(
            '{}{{transport}}{}'.format(
                '', ''
            )
        )

    if username:
        cmd.append(
            '{}{{username}}{}'.format(
                '', ''
            )
        )

    if serveraddress:
        cmd.append(
            '{}{{serveraddress}}{}'.format(
                '', ''
            )
        )

    if filename:
        cmd.append(
            '{}{{filename}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_copy_core_dump(result)


def traceroute(
    enode, destination, min_ttl='', max_ttl='', dst_port='',
    time_out='', probes='', ip_option_source='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Send IPv4 traceroute

    This function runs the following vtysh command:

    ::

        # traceroute {destination}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param destination: <A.B.C.D> IPv4 address.
    :param min_ttl: Minimum number of hops to reach the destination <1-255>.
    :param max_ttl: Maximum number of hops to reach the destination <1-255>.
    :param dst_port: Destination port <1-34000>.
    :param time_out: Traceroute timeout in seconds <1-60>.
    :param probes: Number of Probes <1-5>.
    :param ip_option_source: Source for loose source route record.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_traceroute(result)


def traceroute6(
    enode, destination, max_ttl='', dst_port='', time_out='',
    probes='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Send IPv6 traceroute

    This function runs the following vtysh command:

    ::

        # traceroute6 {destination}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param destination: <X:X::X:X> IPv6 address.
    :param max_ttl: Maximum number of hops to reach the destination <1-255>.
    :param dst_port: Destination port <1-34000>.
    :param time_out: Traceroute timeout in seconds <1-60>.
    :param probes: Number of Probes <1-5>.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_traceroute6(result)


def show_ntp_associations(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show NTP Association summary.

    This function runs the following vtysh command:

    ::

        # show ntp associations

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_associations`
    """

    cmd = [
        'show ntp associations'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ntp_associations(result)


def show_ntp_authentication_key(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show NTP Authentication Keys information.

    This function runs the following vtysh command:

    ::

        # show ntp authentication-key

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_authentication_key`
    """

    cmd = [
        'show ntp authentication-key'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ntp_authentication_key(result)


def show_ntp_statistics(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show NTP Statistics information.

    This function runs the following vtysh command:

    ::

        # show ntp statistics

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_statistics`
    """

    cmd = [
        'show ntp statistics'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ntp_statistics(result)


def show_ntp_status(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show NTP Status information.

    This function runs the following vtysh command:

    ::

        # show ntp status

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_status`
    """

    cmd = [
        'show ntp status'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ntp_status(result)


def show_ntp_trusted_keys(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show NTP Trusted Keys information.

    This function runs the following vtysh command:

    ::

        # show ntp trusted-keys

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ntp_trusted_keys`
    """

    cmd = [
        'show ntp trusted-keys'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ntp_trusted_keys(result)


def show_dhcp_server_leases(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show DHCP server leases information.

    This function runs the following vtysh command:

    ::

        # show dhcp-server leases

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_dhcp_server_leases`
    """

    cmd = [
        'show dhcp-server leases'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_dhcp_server_leases(result)


def show_dhcp_server(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display DHCP server configuration.

    This function runs the following vtysh command:

    ::

        # show dhcp-server

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_dhcp_server`
    """

    cmd = [
        'show dhcp-server'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_dhcp_server(result)


def show_mac_address_table(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display L2 MAC address table information.

    This function runs the following vtysh command:

    ::

        # show mac-address-table

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_mac_address_table`
    """

    cmd = [
        'show mac-address-table'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_mac_address_table(result)


def show_vlog_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlog config.

    This function runs the following vtysh command:

    ::

        # show vlog config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config`
    """

    cmd = [
        'show vlog config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_config(result)


def show_vlog(
    enode, sub_command,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show vlog sub command.

    This function runs the following vtysh command:

    ::

        # show vlog {sub_command}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param sub_command: sub command
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog`
    """

    cmd = [
        'show vlog {sub_command}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog(result)


def show_interface_loopback(
    enode, loopback_int='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show loopback interfaces on ops

    This function runs the following vtysh command:

    ::

        # show interface loopback

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param loopback_int: Loopback interface id.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
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

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_loopback(result)


def show_interface_loopback_brief(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display information for L3 loopback interfaces

    This function runs the following vtysh command:

    ::

        # show interface loopback brief

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_interface_loopback_brief`
    """

    cmd = [
        'show interface loopback brief'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_interface_loopback_brief(result)


def show_vlog_config_daemon(
    enode, daemon_name,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlog config for ops-daemons.

    This function runs the following vtysh command:

    ::

        # show vlog config daemon {daemon_name}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param daemon_name: daemon name
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config_daemon`
    """

    cmd = [
        'show vlog config daemon {daemon_name}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_config_daemon(result)


def show_vlog_config_feature(
    enode, feature_name,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlog config for feature

    This function runs the following vtysh command:

    ::

        # show vlog config feature {feature_name}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param feature_name: feature name
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config_feature`
    """

    cmd = [
        'show vlog config feature {feature_name}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_config_feature(result)


def show_vlog_config_list(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlog config for supported features list

    This function runs the following vtysh command:

    ::

        # show vlog config list

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_config_list`
    """

    cmd = [
        'show vlog config list'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_config_list(result)


def show_vlog_daemon(
    enode, daemon_name,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlogs for ops-daemon

    This function runs the following vtysh command:

    ::

        # show vlog daemon {daemon_name}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param daemon_name: daemon name
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_daemon`
    """

    cmd = [
        'show vlog daemon {daemon_name}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_daemon(result)


def show_vlog_severity(
    enode, severity_level,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlogs for severity level

    This function runs the following vtysh command:

    ::

        # show vlog severity {severity_level}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param severity_level: severity level
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_severity`
    """

    cmd = [
        'show vlog severity {severity_level}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_severity(result)


def show_vlog_daemon_severity(
    enode, daemonname, severity,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlogs for ops-daemon with severity

    This function runs the following vtysh command:

    ::

        # show vlog daemon {daemonname} severity {severity}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param daemonname: daemon name
    :param severity: severity level
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_daemon_severity`
    """

    cmd = [
        'show vlog daemon {daemonname} severity {severity}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_daemon_severity(result)


def show_vlog_severity_daemon(
    enode, severity, daemonname,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vlogs for severity with ops-daemon

    This function runs the following vtysh command:

    ::

        # show vlog severity {severity} daemon {daemonname}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param severity: severity level
    :param daemonname: daemon name
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlog_severity_daemon`
    """

    cmd = [
        'show vlog severity {severity} daemon {daemonname}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlog_severity_daemon(result)


def copy_running_config_startup_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    copies running config to startup config

    This function runs the following vtysh command:

    ::

        # copy running-config startup-config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_copy_running_config_startup_config`
    """

    cmd = [
        'copy running-config startup-config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_copy_running_config_startup_config(result)


def copy_startup_config_running_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    copies startup config to running config

    This function runs the following vtysh command:

    ::

        # copy startup-config running-config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_copy_startup_config_running_config`
    """

    cmd = [
        'copy startup-config running-config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_copy_startup_config_running_config(result)


def show_startup_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show startup-config information.

    This function runs the following vtysh command:

    ::

        # show startup-config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_startup_config`
    """

    cmd = [
        'show startup-config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_startup_config(result)


def erase_startup_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Erase startup-config information.

    This function runs the following vtysh command:

    ::

        # erase startup-config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_erase_startup_config`
    """

    cmd = [
        'erase startup-config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_erase_startup_config(result)


def show_tftp_server(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display TFTP-Server configuration.

    This function runs the following vtysh command:

    ::

        # show tftp-server

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_tftp_server`
    """

    cmd = [
        'show tftp-server'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_tftp_server(result)


def show_mirror(
    enode, name='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show mirroring session information.

    This function runs the following vtysh command:

    ::

        # show mirror

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param name: Up to 64 letters, numbers, underscores, dashes, or periods.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_mirror`
    """

    cmd = [
        'show mirror'
    ]

    if name:
        cmd.append(
            '{}{{name}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_mirror(result)


def show_qos_cos_map(
    enode, default='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows the qos cos-map.

    This function runs the following vtysh command:

    ::

        # show qos cos-map

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param default: Show the default cos-map.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_qos_cos_map`
    """

    cmd = [
        'show qos cos-map'
    ]

    if default:
        cmd.append(
            '{}{{default}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_qos_cos_map(result)


def show_qos_dscp_map(
    enode, default='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows the qos dscp-map.

    This function runs the following vtysh command:

    ::

        # show qos dscp-map

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param default: Show the default dscp-map.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_qos_dscp_map`
    """

    cmd = [
        'show qos dscp-map'
    ]

    if default:
        cmd.append(
            '{}{{default}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_qos_dscp_map(result)


def show_qos_queue_profile(
    enode, queue_profile_name='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows the qos queue profile.

    This function runs the following vtysh command:

    ::

        # show qos queue-profile

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param queue_profile_name: Up to 64 letters, numbers, underscores, dashes,
     or periods.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_qos_queue_profile`
    """

    cmd = [
        'show qos queue-profile'
    ]

    if queue_profile_name:
        cmd.append(
            '{}{{queue_profile_name}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_qos_queue_profile(result)


def show_qos_schedule_profile(
    enode, schedule_profile_name='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows the qos schedule profile.

    This function runs the following vtysh command:

    ::

        # show qos schedule-profile

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param schedule_profile_name: Up to 64 letters, numbers, underscores,
     dashes, or periods.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_qos_schedule_profile`
    """

    cmd = [
        'show qos schedule-profile'
    ]

    if schedule_profile_name:
        cmd.append(
            '{}{{schedule_profile_name}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_qos_schedule_profile(result)


def show_qos_trust(
    enode, default='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows the qos trust.

    This function runs the following vtysh command:

    ::

        # show qos trust

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param default: Show the default qos trust.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_qos_trust`
    """

    cmd = [
        'show qos trust'
    ]

    if default:
        cmd.append(
            '{}{{default}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_qos_trust(result)


def show_snmp_community(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display SNMP configured community names.

    This function runs the following vtysh command:

    ::

        # show snmp community

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_community`
    """

    cmd = [
        'show snmp community'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_snmp_community(result)


def show_snmp_system(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display SNMP system information.

    This function runs the following vtysh command:

    ::

        # show snmp system

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_system`
    """

    cmd = [
        'show snmp system'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_snmp_system(result)


def show_snmp_trap(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display SNMP host information of trap receivers.

    This function runs the following vtysh command:

    ::

        # show snmp trap

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_trap`
    """

    cmd = [
        'show snmp trap'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_snmp_trap(result)


def diag_dump_lacp_basic(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Displays diagnostic information for LACP

    This function runs the following vtysh command:

    ::

        # diag-dump lacp basic

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_diag_dump_lacp_basic`
    """

    cmd = [
        'diag-dump lacp basic'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_diag_dump_lacp_basic(result)


def show_snmpv3_users(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display SNMPV3 users.

    This function runs the following vtysh command:

    ::

        # show snmpv3 users

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmpv3_users`
    """

    cmd = [
        'show snmpv3 users'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_snmpv3_users(result)


def show_core_dump(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display core dumps present

    This function runs the following vtysh command:

    ::

        # show core-dump

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_core_dump`
    """

    cmd = [
        'show core-dump'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_core_dump(result)


def show_snmp_agent_port(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display SNMP agent port configuration.

    This function runs the following vtysh command:

    ::

        # show snmp agent-port

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_snmp_agent_port`
    """

    cmd = [
        'show snmp agent-port'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_snmp_agent_port(result)


def show_events(
    enode, filter='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show system related event logs.

    This function runs the following vtysh command:

    ::

        # show events

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param filter: Optional, filters by category, event-id or severity (filter
     value)
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_events`
    """

    cmd = [
        'show events'
    ]

    if filter:
        cmd.append(
            '{}{{filter}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_events(result)


def show_aaa_authentication(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    AAA authentication infomation.

    This function runs the following vtysh command:

    ::

        # show aaa authentication

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_aaa_authentication`
    """

    cmd = [
        'show aaa authentication'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_aaa_authentication(result)


def show_radius_server(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Radius Server infomation.

    This function runs the following vtysh command:

    ::

        # show radius-server

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_radius_server`
    """

    cmd = [
        'show radius-server'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_radius_server(result)


def diag_dump(
    enode, list='', daemon='', level='', file='',
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display diagnostics dump that supports diag-dump.

    This function runs the following vtysh command:

    ::

        # diag-dump

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param list: Optional, display daemons list that are supporting the
     featured.
    :param daemon: Optional, supported daemon name whose diagnostics are to be
     requested.
    :param level: Optional, takes the string values either basic or advanced.
    :param file: Optional, takes the string values either filename where the
     output get dumped.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_diag_dump`
    """

    cmd = [
        'diag-dump'
    ]

    if list:
        cmd.append(
            '{}{{list}}{}'.format(
                '', ''
            )
        )

    if daemon:
        cmd.append(
            '{}{{daemon}}{}'.format(
                '', ''
            )
        )

    if level:
        cmd.append(
            '{}{{level}}{}'.format(
                '', ''
            )
        )

    if file:
        cmd.append(
            '{}{{file}}{}'.format(
                '', ''
            )
        )

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_diag_dump(result)


def show_spanning_tree(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows priority, address, Hello-time, Max-age, Forward-delay for bridge
    and root node.

    This function runs the following vtysh command:

    ::

        # show spanning-tree

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_spanning_tree`
    """

    cmd = [
        'show spanning-tree'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_spanning_tree(result)


def show_spanning_tree_mst(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows MSTP instance and corresponding VLANs.

    This function runs the following vtysh command:

    ::

        # show spanning-tree mst

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_spanning_tree_mst`
    """

    cmd = [
        'show spanning-tree mst'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_spanning_tree_mst(result)


def show_spanning_tree_mst_config(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows global MSTP configuration

    This function runs the following vtysh command:

    ::

        # show spanning-tree mst-config

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_spanning_tree_mst_config`
    """

    cmd = [
        'show spanning-tree mst-config'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_spanning_tree_mst_config(result)


def show_vlan_summary(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows VLAN summary information.

    This function runs the following vtysh command:

    ::

        # show vlan summary

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlan_summary`
    """

    cmd = [
        'show vlan summary'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlan_summary(result)


def show_vlan_internal(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Shows internal VLAN information.

    This function runs the following vtysh command:

    ::

        # show vlan internal

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vlan_internal`
    """

    cmd = [
        'show vlan internal'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vlan_internal(result)


def show_vrf(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show vrf information.

    This function runs the following vtysh command:

    ::

        # show vrf

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vrf`
    """

    cmd = [
        'show vrf'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vrf(result)


def show_access_list_hitcounts_ip_interface(
    enode, acl_name, port,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Show hit-counts per ACE aggregated across ports.

    This function runs the following vtysh command:

    ::

        # show access-list hitcounts ip {acl_name} interface {port}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param acl_name: Access-list name.
    :param port: Label that identifies interface.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_access_list_hitcounts_ip_interface`
    """

    cmd = [
        'show access-list hitcounts ip {acl_name} interface {port}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_access_list_hitcounts_ip_interface(result)


def show_ip_prefix_list(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display IP prefix list information.

    This function runs the following vtysh command:

    ::

        # show ip prefix-list

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_prefix_list`
    """

    cmd = [
        'show ip prefix-list'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_prefix_list(result)


def show_ipv6_prefix_list(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display IPv6 prefix list information

    This function runs the following vtysh command:

    ::

        # show ipv6 prefix-list

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ipv6_prefix_list`
    """

    cmd = [
        'show ipv6 prefix-list'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ipv6_prefix_list(result)


def show_ip_bgp_route_map(
    enode, rmap,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display route-map information

    This function runs the following vtysh command:

    ::

        # show ip bgp route-map {rmap}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param rmap: Route-map name
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_ip_bgp_route_map`
    """

    cmd = [
        'show ip bgp route-map {rmap}'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_ip_bgp_route_map(result)


def show_vrrp(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vrrp information

    This function runs the following vtysh command:

    ::

        # show vrrp

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vrrp`
    """

    cmd = [
        'show vrrp'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vrrp(result)


def show_vrrp_brief(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display vrrp brief information

    This function runs the following vtysh command:

    ::

        # show vrrp brief

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_vrrp_brief`
    """

    cmd = [
        'show vrrp brief'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_vrrp_brief(result)


def show_date(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display system date information

    This function runs the following vtysh command:

    ::

        # show date

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_date`
    """

    cmd = [
        'show date'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_date(result)


def show_system_timezone(
    enode,
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    Display system timezone information

    This function runs the following vtysh command:

    ::

        # show system timezone

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.parse_show_system_timezone`
    """

    cmd = [
        'show system timezone'
    ]

    shell = enode.get_shell(_shell)

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )

    return parse_show_system_timezone(result)


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
    'ConfigQueueProfile',
    'ConfigScheduleProfile',
    'ConfigAccessListIpTestname',
    'ConfigVrrpInterface',
    'show_interface',
    'show_interface_brief',
    'show_interface_mgmt',
    'show_interface_subinterface',
    'show_interface_subinterface_brief',
    'show_interface_queues',
    'show_vlan',
    'show_lacp_interface',
    'show_lacp_aggregates',
    'show_lacp_configuration',
    'show_lldp_neighbor_info',
    'show_lldp_statistics',
    'show_sftp_server',
    'show_ip_interface',
    'show_ipv6_interface',
    'show_ip_bgp_summary',
    'show_ip_bgp_neighbors',
    'show_ip_bgp',
    'show_ipv6_bgp',
    'show_ip_ospf_neighbor_detail',
    'show_ip_ospf_neighbor',
    'show_ip_ospf_interface',
    'show_ip_ospf',
    'show_ip_ospf_route',
    'show_running_config',
    'show_running_config_interface',
    'show_ip_route',
    'show_ipv6_route',
    'show_sflow',
    'show_sflow_interface',
    'show_udld_interface',
    'show_rib',
    'show_ip_ecmp',
    'show_version',
    'show_arp',
    'clear_bgp',
    'clear_udld_statistics',
    'clear_udld_statistics_interface',
    'clear_access_list_hitcounts_all',
    'clear_access_list_hitcounts_ip_interface',
    'ping_repetitions',
    'ping6_repetitions',
    'ping',
    'ping6',
    'copy_core_dump',
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
    'copy_startup_config_running_config',
    'show_startup_config',
    'erase_startup_config',
    'show_tftp_server',
    'show_mirror',
    'show_qos_cos_map',
    'show_qos_dscp_map',
    'show_qos_queue_profile',
    'show_qos_schedule_profile',
    'show_qos_trust',
    'show_snmp_community',
    'show_snmp_system',
    'show_snmp_trap',
    'diag_dump_lacp_basic',
    'show_snmpv3_users',
    'show_core_dump',
    'show_snmp_agent_port',
    'show_events',
    'show_aaa_authentication',
    'show_radius_server',
    'diag_dump',
    'show_spanning_tree',
    'show_spanning_tree_mst',
    'show_spanning_tree_mst_config',
    'show_vlan_summary',
    'show_vlan_internal',
    'show_vrf',
    'show_access_list_hitcounts_ip_interface',
    'show_ip_prefix_list',
    'show_ipv6_prefix_list',
    'show_ip_bgp_route_map',
    'show_vrrp',
    'show_vrrp_brief',
    'show_date',
    'show_system_timezone'
]
