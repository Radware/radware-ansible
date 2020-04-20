#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, Radware LTD.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: alteon_software_install
short_description: Install software image on device 
description:
  - Install software image on Alteon device
version_added: null
author: 
  - Leon Meguira (@leonmeguira)
options:
  provider:
    description:
      - Radware Alteon connection details.
    required: true
    suboptions:
      server:
        description:
          - Radware Alteon IP.
        required: true
        default: null
      user:
        description:
          - Radware Alteon username.
        required: true
        default: null
      password:
        description:
          - Radware Alteon password.
        required: true
        default: null
      validate_certs:
        description:
          - If C(no), SSL certificates will not be validated.
          - This should only set to C(no) used on personally controlled sites using self-signed certificates.
        required: true
        default: null
        type: bool
      https_port:
        description:
          - Radware Alteon https port.
        required: true
        default: null
      ssh_port:
        description:
          - Radware Alteon ssh port.
        required: true
        default: null
      timeout:
        description:
          - Timeout for connection.
        required: true
        default: null
  state:
    description:
      - When C(installed), ensure the software installed on the device and the is set to be booted 
        from. the device is not rebooted into the new software if needed.
      - When C(activated), performs the same operation as C(installed), but the system is rebooted into the new software
    required: false
    default: activated
    choices:
      - installed
      - activated
  version:
    description:
      - software version
    required: true
    default: null
    type: str
  reboot_wait:
    description:
      - when C(yes) wait for device to return after reboot.
      - when C(no) no wait for device to return after reboot
    required: false
    default: yes
    type: bool
  reboot_timeout:
    description:
      - Stateful Reboot timeout in seconds.
    required: false
    default: 600
    type: int
  reboot_wait_vadc:
    description:
      - when C(yes) wait for vadcs to return after device reboot.
      - when C(no) no wait for vadcs to return after device reboot
      - applicable on VX and when reboot_wait = yes
    required: false
    default: no
    type: bool
  reboot_vadc_timeout:
    description:
      - vadc wait timeout in seconds.
    required: false
    default: 180
    type: int
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon software installation
  alteon_software_install:
    provider: 
      server: 192.168.1.1
      user: admin
      password: admin
      validate_certs: no
      https_port: 443
      ssh_port: 22
      timeout: 5
    state: activated
    version: 31.0.10.50
    reboot_wait: yes
    reboot_timeout: 600
'''

RETURN = r'''
status:
  description: Message detailing run result
  returned: success
  type: str
  sample: Software Installed successfully
'''

from ansible.module_utils.basic import AnsibleModule
import traceback

from ansible.module_utils.network.radware.common import RadwareModuleError
from ansible.module_utils.network.radware.alteon import AlteonManagementModule, AlteonManagementFunctionArgumentSpec
from radware.alteon.sdk.alteon_managment import AlteonMngOper


class ArgumentSpecs(AlteonManagementFunctionArgumentSpec):
    def __init__(self):
        super().__init__(AlteonMngOper.software_install)
        self.argument_spec.update(state=dict(
            choices=['installed', 'activated'],
            default='activated'
        ))


class ModuleManager(AlteonManagementModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(AlteonMngOper, command='software_install', **kwargs)

    def exec_module(self):
        if self.params['state'] == 'installed':
            res = super().exec_module(reboot=False)
        else:
            res = super().exec_module(reboot=True)

        res['changed'] = res['status']
        if res['status']:
            res['status'] = 'Software Installed successfully'
        else:
            res['status'] = 'Software already Installed'
        return res


def main():
    spec = ArgumentSpecs()
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
