#!/usr/bin/python
#
# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from abc import abstractmethod
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.radware.common import BaseAPI, RadwareModuleError, radware_server_argument_spec, \
    build_specs_from_annotation
try:
    from radware.sdk.api import BaseDeviceConnection
    from radware.sdk.exceptions import RadwareError
    from radware.sdk.management import DeviceManagement
    from radware.sdk.configurator import DeviceConfigurationManager, ConfigManagerResult, MSG_NO_CHANGE
except ModuleNotFoundError:
    AnsibleModule(argument_spec={}, check_invalid_arguments=False).fail_json(
        msg="The radware-sdk-common package is required")


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: Device Configurator module
author:
  - Leon Meguira (@leonmeguira)
'''

DEFAULT_STATE = ['present', 'absent']
EXCLUDE_STATE = ['read_all']
SDK_TO_ANSIBLE_CMD = {
    'deploy': 'overwrite',
    'delete': 'absent',
    'update': 'append'
}
ANSIBLE_TO_SDK_CMD = {
    'overwrite': 'deploy',
    'absent': 'delete',
    'present': 'update',
    'append': 'update'
}


def configuration_choice_translation(sdk_choices):
    choices = list()
    choices.extend(DEFAULT_STATE)
    for item in sdk_choices:
        if item in EXCLUDE_STATE:
            continue
        if item in SDK_TO_ANSIBLE_CMD:
            if SDK_TO_ANSIBLE_CMD[item] not in DEFAULT_STATE:
                choices.append(SDK_TO_ANSIBLE_CMD[item])
        else:
            choices.append(item)
    return choices


class ConfigurationArgumentSpec(object):
    def __init__(self, config_class):
        self.supports_check_mode = True
        argument_spec = dict(
            parameters=dict(
                required=False,
                type='dict',
                options=build_specs_from_annotation(config_class.get_parameters_class())
            ),
            state=dict(
                required=True,
                choices=configuration_choice_translation(config_class.api_function_names())
            ),
            write_on_change=dict(
                required=False,
                type='bool',
                default=False
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(radware_server_argument_spec)
        self.argument_spec.update(argument_spec)


class ConfigurationModule(BaseAPI):
    def __init__(self, configurator_class, **kwargs):
        self._configurator = configurator_class(self._device_connection)
        self._config_manager = DeviceConfigurationManager()
        self._state = self._base.params['state']
        self._write_on_change = self._base.params['write_on_change']
        if self._state == 'present':
            self._differential_update = True
        else:
            self._differential_update = False

        self.arguments = configurator_class.get_parameters_class()()
        if self._base.params['parameters'] is None:
            self._base.params['parameters'] = dict()
        self.arguments.set_attributes(**self._base.params['parameters'])
        self.result = {}
        self.changed = False
        self.changes = None
        if hasattr(self._base.module, '_diff'):
            self._report_diff = getattr(self._base.module, '_diff')
        else:
            self._report_diff = False

    @abstractmethod
    def _on_error(self):
        pass

    @property
    def command(self):
        if self._state in ANSIBLE_TO_SDK_CMD:
            return ANSIBLE_TO_SDK_CMD[self._state]
        else:
            return self._state

    def exec_module(self):
        def prepare_object():
            device_current = self._config_manager.execute(self._configurator, 'read', self.arguments).content_translate
            if device_current is None:
                return self._base.params['parameters']
            if self._base.module.check_mode:
                if '---' in self.changes:
                    for key in self.changes['---'].keys():
                        if key in device_current:
                            if type(self.changes['---'][key]) == list:
                                for item in self.changes['---'][key]:
                                    device_current[key].remove(item)
                            else:
                                del device_current[key]
                if '+++' in self.changes:
                    for key in self.changes['+++'].keys():
                        if type(self.changes['+++'][key]) == list:
                            if type(device_current[key]) != list:
                                device_current[key] = []
                            for item in self.changes['+++'][key]:
                                device_current[key].append(item)
                        else:
                            device_current[key] = self.changes['+++'][key]
            return device_current

        # try:
        #     self._device_mng.verify_device_accessible(retries=2)
        # except RadwareError as e:
        #     raise RadwareModuleError(e)

        try:
            conf_mng_result = self._config_manager.execute(self._configurator, self.command, self.arguments,
                                                           dry_run=self._base.module.check_mode,
                                                           differential=self._differential_update,
                                                           write_on_change=self._write_on_change,
                                                           get_diff=True)
            if conf_mng_result.diff:
                self.changed = True
                self.changes = conf_mng_result.diff
        except RadwareError as e:
            self._on_error()
            raise RadwareModuleError(e)

        if self.changed:
            self.result.update(dict(changed=self.changed))
            if self._report_diff:
                self.result.update(dict(diff=self.changes))
            self.result.update(status=conf_mng_result.content_translate, obj=prepare_object())
        else:
            if self._state in ANSIBLE_TO_SDK_CMD:
                self.result.update(status=MSG_NO_CHANGE, obj=None)
            else:
                if self._state == 'read':
                    read_result = conf_mng_result.content_translate
                    if read_result:
                        self.result.update(status='found', obj=read_result)
                    else:
                        self.result.update(status='not found', obj=read_result)
                else:
                    self.result.update(status=conf_mng_result.content_translate, obj=None)
        return self.result


