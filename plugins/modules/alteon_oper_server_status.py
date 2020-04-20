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
module: alteon_oper_server_status
short_description: Set Alteon Real Server operational status
description:
  - Set real server operational status
  - the module set 'changed' flag if server state has changed
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
  name:
    description:
      - server index
    required: true
    type: str
  status:
    description:
      - Real server operational status.
    required: false
    default: null
    type: str
    choices:
    - enable
    - disable
    - cookiepersistent
    - fastage
    - cookiepersistentfastage
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon set real server operational state
  alteon_oper_server_status:
    provider: 
      server: 192.168.1.1
      user: admin
      password: admin
      validate_certs: no
      https_port: 443
      ssh_port: 22
      timeout: 5
    name: server1
    status: disable
'''

RETURN = r'''
status:
  description: Message detailing run result
  returned: success
  type: str
  sample: Server status changed
'''

from ansible.module_utils.basic import AnsibleModule
import traceback

from ansible.module_utils.network.radware.common import RadwareModuleError
from ansible.module_utils.network.radware.alteon import AlteonManagementModule, AlteonManagementFunctionArgumentSpec
from radware.alteon.sdk.alteon_managment import AlteonMngOper


class ArgumentSpecs(AlteonManagementFunctionArgumentSpec):
    def __init__(self):
        super().__init__(AlteonMngOper.set_server_state)


class ModuleManager(AlteonManagementModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(AlteonMngOper, command='set_server_state', **kwargs)

    def exec_module(self):
        res = super().exec_module()
        res['changed'] = res['status']
        res['status'] = 'Server status changed' if res['status'] else 'Server status unchanged'
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
