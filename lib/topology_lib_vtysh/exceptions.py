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
Vtysh auto-generated typed exceptions module.

.. warning::

   This is auto-generated, do not modify manually!!
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from re import match
from collections import OrderedDict


class VtyshException(Exception):
    """
    Base exception class for vtysh shell errors.

    :param str output: The shell output that triggered this exception.
    """
    def __init__(self, output):
        super(VtyshException, self).__init__()
        self.output = output


class UnknownVtyshException(VtyshException):
    """
    Generic exception raised when the specific exception could not be
    determined.
    """


class UnknownCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        Unknown command
        % Unknown command.

    """


class IncompleteCommandException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        Command incomplete

    """


class NotValidLAG(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        Specified LAG port does not exist.

    """


class DuplicateLoopbackIPException(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::
        IP address is already assigned to interface. [A-Za-z0-9]+             as primary.

    """


VTYSH_EXCEPTIONS = OrderedDict([
    (
        UnknownCommandException,
        [
            'Unknown command',
            '% Unknown command.',
        ]
    ),
    (
        IncompleteCommandException,
        [
            'Command incomplete',
        ]
    ),
    (
        NotValidLAG,
        [
            'Specified LAG port does not exist.',
        ]
    ),
    (
        DuplicateLoopbackIPException,
        [
            'IP address is already assigned to interface. [A-Za-z0-9]+             as primary.',
        ]
    ),
])


def determine_exception(output):
    """
    Determine which exception to raise from shell error message.

    :param str output: The shell output error.
    :rtype: VtyshException subclass.
    :return: The corresponding exception class for given message.
    """
    for exc, matches in VTYSH_EXCEPTIONS.items():
        for expression in matches:
            if match(expression, output):
                return exc
    return UnknownVtyshException


__all__ = [
    'VtyshException',
    'UnknownVtyshException',
    'UnknownCommandException',
    'IncompleteCommandException',
    'NotValidLAG',
    'DuplicateLoopbackIPException',
    'VTYSH_EXCEPTIONS',
    'determine_exception'
]
