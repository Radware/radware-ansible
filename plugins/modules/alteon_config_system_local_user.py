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
module: alteon_config_system_local_user
short_description: Manage local users in Radware Alteon
description:
  - Manage local users in Radware Alteon.
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
  state:
    description:
      - When C(present), guarantees that the object exists with the provided attributes.
      - When C(absent), when applicable removes the object.
      - When C(read), when exists read object from configuration to parameter format.
      - When C(overwrite), removes the object if exists then recreate it
      - When C(append), append object configuration with the provided parameters
    required: true
    default: null
    choices:
    - present
    - absent
    - read
    - overwrite
    - append
  revert_on_error:
    description:
      - If an error occurs, perform revert on alteon.
    required: false
    default: false
    type: bool
  write_on_change:
    description:
      - Executes Alteon write calls only when an actual change has been evaluated.
    required: false
    default: false
    type: bool
  parameters:
    description:
      - Parameters local users configuration.
    suboptions:
      index:
        description:
          - The user identifier.
        required: true
        default: null
        type: int
      user_role:
        description:
          - The user class of service.
        required: false
        default: user
        choices:
        - user
        - crtadmin
        - slboper
        - l4oper
        - oper
        - slbadmin
        - l4admin
        - admin
        - slbview
        - l3oper
        - l3admin
        - l1oper
        - l2oper
        - wsadmin
        - wsowner
        - wsview
      user_name:
        description:
          - The username for the local user.
        required: false
        default: null
        type: str
      state:
        description:
          - Specifies whether to enable the user.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      admin_password:
        description:
          - The character string representing the current administrator password.
        required: false
        default: null
        type: str
      user_password:
        description:
          - The character string representing the user password.
        required: false
        default: null
        type: str
      radius_tacacs_fallback:
        description:
          - Specifies whether to enable back-door administrator access.
          - When back-door administrator access is enabled, the user can log in to Telnet/SSH/Web UI using administrator credentials when the TACACS+ server is down.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      language_display:
        description:
          - Sets the Alteon Web Based Management (WBM) interface language for a local user.
        required: false
        default: english
        choices:
        - english
        - chinese
        - korean
        - japanese
      ssh_key:
        description:
          - user open-ssh txt public key or SSH2 public key.
        required: false
        default: null
        type: str
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_system_local_user:
    provider: 
      server: 192.168.1.1
      user: admin
      password: admin
      validate_certs: no
      https_port: 443
      ssh_port: 22
      timeout: 5
    state: present
    parameters:
      index: 7
      user_name: nati
      state: enabled
      admin_password: admin
      user_password: radware
      radius_tacacs_fallback: enabled
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EA...
'''

RETURN = r'''
status:
  description: Message detailing run result
  returned: success
  type: str
  sample: object deployed successfully
obj:
  description: parameters object type
  returned: changed, read
  type: dictionary
'''

from ansible.module_utils.basic import AnsibleModule
import traceback

from ansible.module_utils.network.radware.common import RadwareModuleError
from ansible.module_utils.network.radware.alteon import AlteonConfigurationModule, \
    AlteonConfigurationArgumentSpec as ArgumentSpec
from radware.alteon.sdk.configurators.system_local_user import LocalUserConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(LocalUserConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(LocalUserConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
