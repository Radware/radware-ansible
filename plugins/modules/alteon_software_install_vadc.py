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
module: alteon_software_install_vadc
short_description: Install software image on vadc 
description:
  - Install software image on Alteon device
  - applicable on VX 
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
      - When C(installed), ensure the vadc software installed on the device and the is set to be booted  
        from. the vadcs are not rebooted into the new software if needed.
      - When C(activated), performs the same operation as C(installed), but the vadcs are rebooted into the new software
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
  vadc_id:
    description:
      - vadc id
    required: true
    default: null
    type: int
  reboot_wait:
    description:
      - when C(yes) wait for vadc to return after reboot.
      - when C(no) no wait for vadc to return after reboot
    required: false
    default: yes
    type: bool
  reboot_timeout:
    description:
      - Stateful Reboot timeout in seconds.
    required: false
    default: 180
    type: int
  vadc_user:
    description:
      - vadc login user name for software installation validation
      - if unspecified, vx login user is used 
    required: false
    default: null
    type: str
  vadc_password:
    description:
      - vadc login password for software installation validation
      - if unspecified, vx login password is used 
    required: false
    default: null
    type: str
    type: bool
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
    vadc_id: 2
    version: 31.0.10.50
    reboot_wait: yes
    reboot_timeout: 180
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
        super().__init__(AlteonMngOper.software_install_vadc)
        self.argument_spec.update(state=dict(
            choices=['installed', 'activated'],
            default='activated'
        ))


class ModuleManager(AlteonManagementModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(AlteonMngOper, command='software_install_vadc', **kwargs)

    def exec_module(self):
        if self.params['state'] == 'installed':
            res = super().exec_module(reboot=False)
            mode = 'Installed'
        else:
            res = super().exec_module(reboot=True)
            mode = 'Activated'

        if res['status']:
            return dict(status='Software {} successfully'.format(mode), changed=True)
        else:
            return dict(status='No Software {}'.format(mode), changed=False)


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
