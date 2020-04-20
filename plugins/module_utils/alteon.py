#!/usr/bin/python
#
# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.radware.configuration import ConfigurationArgumentSpec, ConfigurationModule
from ansible.module_utils.network.radware.common import RadwareBaseModule, radware_server_argument_spec
from ansible.module_utils.network.radware.management import ManagementArgumentSpec, ManagementFunctionArgumentSpec, \
    ManagementModule
try:
    from radware.alteon.api.mgmt import AlteonManagement
    from radware.alteon.api import AlteonDeviceConnection
    from radware.sdk.exceptions import RadwareError
    from radware.alteon import __minimum_supported_version__
except ModuleNotFoundError:
    AnsibleModule(argument_spec={}, check_invalid_arguments=False).fail_json(
        msg="The alteon-sdk package is required")


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: Alteon Management and Configuration module
author:
  - Leon Meguira (@leonmeguira)
'''


def fail_on_pending_arg_spec(argument_spec: dict):
    fail_on_pending_cfg_spec = dict(
        fail_on_pending_cfg=dict(
            required=False,
            type='bool',
            default=False
        )
    )
    argument_spec.update(fail_on_pending_cfg_spec)


class AlteonManagementArgumentSpec(ManagementArgumentSpec):
    def __init__(self, mng_class):
        super(AlteonManagementArgumentSpec, self).__init__(mng_class)
        self.argument_spec.update(radware_server_argument_spec)


class AlteonManagementFunctionArgumentSpec(ManagementFunctionArgumentSpec):
    def __init__(self, mng_function, *additional_functions):
        super(AlteonManagementFunctionArgumentSpec, self).__init__(mng_function)
        command_names = list()
        command_names.append(mng_function.__name__)
        if additional_functions:
            for func in additional_functions:
                command_names.append(func.__name__)
            argument_spec = dict(
                command=dict(
                    required=True,
                    choices=command_names
                )
            )
            self.argument_spec.update(argument_spec)
        self.argument_spec.update(radware_server_argument_spec)


class AlteonConfigurationArgumentSpec(ConfigurationArgumentSpec):

    def __init__(self, config_class):
        super(AlteonConfigurationArgumentSpec, self).__init__(config_class)
        additional_argument_spec = dict(
            revert_on_error=dict(
                required=False,
                type='bool',
                default=False
            )
        )
        self.argument_spec.update(additional_argument_spec)


class AlteonAnsibleModule(RadwareBaseModule):
    def __init__(self, **kwargs):
        super(AlteonAnsibleModule, self).__init__(**kwargs)
        self._connection = AlteonDeviceConnection(**self.provider)
        self._mng = AlteonManagement(self._connection)

    def module_warn_alteon_version(self):
        self.module.warn('please verify your alteon is running a version >= {0}'.format(__minimum_supported_version__))


class AlteonManagementModule(AlteonAnsibleModule, ManagementModule):
    def __init__(self, management_class, **kwargs):
        AlteonAnsibleModule.__init__(self, **kwargs)
        ManagementModule.__init__(self, management_class, **kwargs)

    @property
    def _base(self):
        return self

    @property
    def _device_mng(self):
        return self._mng

    @property
    def _device_connection(self):
        return self._connection


class AlteonConfigurationModule(AlteonAnsibleModule, ConfigurationModule):
    def __init__(self, configurator_class, **kwargs):
        AlteonAnsibleModule.__init__(self, **kwargs)
        ConfigurationModule.__init__(self, configurator_class, **kwargs)
        self._revert_on_error = self.params['revert_on_error']

    @property
    def _base(self):
        return self

    @property
    def _device_mng(self):
        return self._mng

    @property
    def _device_connection(self):
        return self._connection

    @property
    def revert_on_error(self):
        return self._revert_on_error

    def _on_error(self):
        self.module_warn_alteon_version()
        if self._revert_on_error:
            self._mng.config.revert()

