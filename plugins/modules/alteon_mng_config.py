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
module: alteon_mng_config
short_description: Manage configuration in Radware Alteon
description:
  - Manage configuration in Radware Alteon.
version_added: null
author: 
  - Leon Meguira (@leonmeguira)
  - Nati Fridman (@natifridman)
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
  command:
    description:
      - Action to run.
      - Use C(apply) to apply pending config changes.
      - Use C(commit) to apply pending config changes. revert on error.
      - Use C(commit_save) commit and save. revert on error.
      - Use C(diff) to show pending config changes.
      - Use C(diff_flash) to show pending config changes between flash and new config.
      - Use C(pending_configuration_validation) to show pending config changes.
      - Use C(revert) to revert pending changes.
      - Use C(revert_apply) to revert applied changes.
      - Use C(save) to save updated config to FLASH.
      - Use C(sync) to sync configuration.
    required: true
    default: null
    choices:
    - apply
    - commit
    - commit_save
    - diff
    - diff_flash
    - pending_configuration_validation
    - revert
    - revert_apply
    - save
    - sync
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_mng_config:
    provider: 
      server: 192.168.1.1
      user: admin
      password: admin
      validate_certs: no
      https_port: 443
      ssh_port: 22
      timeout: 5
    command: apply
'''


RETURN = r'''
status:
  description: Message detailing run result
  returned: success
  type: str
  sample: complete
diff:
  description: diff or diff_flash configuration
  returned: diff, diff_flash
  type: list
pending:
  description: pending configuration state
  returned: diff, diff_flash
  type: bool
'''

from ansible.module_utils.basic import AnsibleModule
import traceback

from ansible.module_utils.network.radware.common import RadwareModuleError
from ansible.module_utils.network.radware.alteon import AlteonManagementArgumentSpec, AlteonManagementModule
from radware.alteon.sdk.alteon_managment import AlteonMngConfig


class ModuleManager(AlteonManagementModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(AlteonMngConfig, **kwargs)

    def exec_mng_config(self):
        changed = False
        if self._command in ['apply', 'commit'] and self._mng_instance.pending_apply():
            changed = True
        if self._command in ['save'] and self._mng_instance.pending_save():
            changed = True
        if self._command == 'commit_save' and (self._mng_instance.pending_apply() or
                                               self._mng_instance.pending_save()):
            changed = True
        if self._command == 'revert' and self._mng_instance.pending_apply():
            changed = True
        if self._command == 'revert_apply' and (self._mng_instance.pending_apply() or
                                                self._mng_instance.pending_save()):
            changed = True

        exec_result = self.exec_module()
        exec_result['changed'] = changed
        func_result = exec_result['status']
        if self._command == 'diff':
            if self._mng_instance.pending_apply():
                exec_result.update(status='pending apply', diff=func_result, pending=True)
            else:
                exec_result.update(status='no pending apply', diff=None, pending=False)
        elif self._command == 'diff_flash':
            if self._mng_instance.pending_save():
                exec_result.update(status='pending save', diff=func_result, pending=True)
            else:
                exec_result.update(status='no pending save', diff=None, pending=False)
        else:
            exec_result.update(status=func_result)
        return exec_result


def main():
    spec = AlteonManagementArgumentSpec(AlteonMngConfig)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_mng_config()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
