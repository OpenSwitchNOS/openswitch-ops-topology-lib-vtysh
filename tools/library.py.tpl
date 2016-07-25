{%- macro param_attrs(attrs) -%}
{% if attrs -%}
, {% for attr in attrs -%}
{{ attr.name|variablize }}
{%- if 'optional' in attr.keys() and attr.optional %}=''{% endif %}
{%- if not loop.last %}, {% endif -%}
{%- endfor %}
{%- endif %}
{%- endmacro -%}
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

from datetime import datetime
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

{% for context_name, context in spec.items() if context_name != 'root' %}
class {{ context_name|objectize }}(ContextManager):
    """
    {{ context.doc|wordwrap(75)|indent(4) }}

    pre_commands:

    ::

        {{ context.pre_commands }}

    post_commands:

    ::

        {{ context.post_commands }}
    """  # noqa
    def __init__({{ 'self, enode%s):'|format(param_attrs(context.arguments))|wordwrap(67)|indent(12) }}
        self.enode = enode
        {%- for arg in context.arguments %}
        {% if arg.name == 'portlbl' -%}
        self.port = enode.ports.get(portlbl, portlbl)
        {%- else -%}
        self.{{ arg.name }} = {{ arg.name }}
        {%- endif %}
        {%- endfor %}

    def __enter__(self):
        commands = """\
        {%- for pre_command in context.pre_commands %}
            {{ pre_command }}
        {%- endfor %}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )

        return self

    def __exit__(self, type, value, traceback):
        commands = """\
        {%- for post_command in context.post_commands %}
            {{ post_command }}
        {%- endfor %}
        """

        self.enode.libs.common.assert_batch(
            commands,
            replace=self.__dict__,
            shell='vtysh'
        )
{% for command in context.commands %}
    def {{ command.command|methodize }}(
        {{ 'self%s,'|format(param_attrs(command.arguments))|wordwrap(56)|indent(8) }}
        _shell='vtysh',
        _shell_args={
            'matches': None,
            'newline': True,
            'timeout': None,
            'connection': None
        }
    ):
        """
        {{ command.doc|wordwrap(71)|indent(8) }}

        This function runs the following vtysh command:

        ::

            # {{ command.command }}{% if command.command|length > 65%} # noqa{% endif %}

        {% for attr in command.arguments -%}
        {{ ':param %s: %s'|format(attr.name, attr.doc)|wordwrap(70)|indent(12) }}
        {% endfor -%}
        :param str _shell: shell to be selected
        :param dict _shell_args: low-level shell API arguments
        {% if 'returns' in command.keys() and command.returns -%}
        :return: A dictionary as returned by
         :func:`topology_lib_vtysh.parser.{{ 'parse_%s_%s'|format(context_name|methodize, command.command|methodize) }}`
        {% endif -%}
        """{% if command.command|length > 66%}  # noqa{% endif %}

        cmd = [
            '{{command.command}}'{% if command.command|length > 65%}  # noqa{% endif %}
        ]
        {%- for attr in command.arguments -%}
            {% if attr.name == 'portlbl' %}

        port = self.enode.ports.get(portlbl, portlbl)
            {%- elif 'optional' in attr.keys() and attr.optional %}

        if {{attr.name}}:
            cmd.append(
                '{{"{}{{"}}{{attr.name}}{{"}}{}"}}'.format(
                    '{{ '' if 'prefix' not in attr.keys() else attr.prefix }}',
                    {{-' '}}'{{ '' if 'suffix' not in attr.keys() else attr.suffix }}'
                )
            )
            {%- endif -%}
        {%- endfor %}

        shell = self.enode.get_shell(_shell)

        print('{} [{}].send_command(\'{}\', shell=\'{}\') ::'.format(
                datetime.now().isoformat(), self.enode.identifier, cmd, shell
        ))

        shell.send_command(
            (' '.join(cmd)).format(**locals()), **_shell_args
        )

        result = shell.get_response(
            connection=_shell_args.get('connection', None)
        )
        print(result)

        {% if 'returns' in command.keys() and command.returns -%}
        {{ 'return parse_%s_%s(result)'|format(context_name|methodize, command.command|methodize) }}
        {%- else -%}
        if result:
            raise determine_exception(result)(result)
        {%- endif %}
{% endfor %}
{% endfor -%}

{% for command in spec.root.commands %}
def {{ command.command|methodize }}(
    {{'enode%s, '|format(param_attrs(command.arguments))|wordwrap(67)|indent(4) }}
    _shell='vtysh',
    _shell_args={
        'matches': None,
        'newline': True,
        'timeout': None,
        'connection': None
    }
):
    """
    {{ command.doc|wordwrap(71)|indent(4) }}

    This function runs the following vtysh command:

    ::

        # {{ command.command }}{% if command.command|length > 68%}  # noqa{% endif %}

    :param dict kwargs: arguments to pass to the send_command of the
     vtysh shell.
    {% for attr in command.arguments -%}
    {{ ':param %s: %s'|format(attr.name, attr.doc)|wordwrap(75)|indent(5) }}
    {% endfor -%}
    :param str _shell: shell to be selected
    :param dict _shell_args: low-level shell API arguments
    {% if 'returns' in command.keys() and command.returns -%}
    :return: A dictionary as returned by
     :func:`topology_lib_vtysh.parser.{{ 'parse_%s'|format(command.command|methodize) }}`
    {% endif -%}
    """{% if command.command|length > 69%}  # noqa{% endif %}

    cmd = [
        '{{command.command}}'
    ]
    {%- for attr in command.arguments -%}
        {% if attr.name == 'portlbl' %}

    port = enode.ports.get(portlbl, portlbl)
        {%- elif 'optional' in attr.keys() and attr.optional %}

    if {{attr.name}}:
        cmd.append(
            '{{"{}{{"}}{{attr.name}}{{"}}{}"}}'.format(
                '{{ '' if 'prefix' not in attr.keys() else attr.prefix }}',
                {{-' '}}'{{ '' if 'suffix' not in attr.keys() else attr.suffix }}'
            )
        )
        {%- endif -%}
    {%- endfor %}

    shell = enode.get_shell(_shell)

    print('{} [{}].send_command(\'{}\', shell=\'{}\') ::'.format(
                datetime.now().isoformat(), enode.identifier, cmd, shell
        ))

    shell.send_command(
        (' '.join(cmd)).format(**locals()), **_shell_args
    )

    result = shell.get_response(
        connection=_shell_args.get('connection', None)
    )
    print(result)

    {% if 'returns' in command.keys() and command.returns -%}
    {{ 'return parse_%s(result)'|format(command.command|methodize) }}
    {%- else -%}
    if result:
        raise determine_exception(result)(result)
    {%- endif %}

{% endfor %}
__all__ = [
    'ContextManager',
{%- for context_name in spec.keys() if context_name != 'root' %}
    '{{ context_name|objectize }}',
{%- endfor %}
{%- for function in spec.root.commands %}
    '{{ function.command|methodize }}'{% if not loop.last %},{% endif %}
{%- endfor %}
]
{# #}
