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
module: alteon_config_system_tacacs_auth
short_description: Manage TACACS+ Authentication in Radware Alteon
description:
  - Manage TACACS+ Authentication in Radware Alteon.
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
      - Parameters for TACACS+ Authentication configuration.
    suboptions:
      state:
        description:
          - Specifies whether to enable TACACS+ authentication.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      port:
        description:
          - The TACACS+ port number.
        required: false
        default: 49
        type: int
      primary_ip4_address:
        description:
          - The IP address of the primary TACACS+ server.
        required: false
        default: null
        type: str
      secondary_ip4_address:
        description:
          - The IP address of the secondary TACACS+ server.
        required: false
        default: null
        type: str
      primary_ip6_address:
        description:
          - The IP address of the primary TACACS+ server.
        required: false
        default: null
        type: str
      secondary_ip6_address:
        description:
          - The IP address of the secondary TACACS+ server.
        required: false
        default: null
        type: str
      timeout_second:
        description:
          - The time, in seconds, before re-sending an authentication to the TACACS+ server after receiving no answer.
        required: false
        default: null
        type: int
      retries:
        description:
          - Number of retries to the TACACS+ server.
        required: false
        default: null
        type: int
      primary_secret:
        description:
          - The TACACS+ authentication string.
        required: false
        default: null
        type: str
      secondary_secret:
        description:
          - The secondary TACACS+ authentication string.
        required: false
        default: null
        type: str
      local_user_priority:
        description:
          - Specifies that Alteon should first search for the user in the Local User Table, and only if not found/authenticated there to connect to the remote authentication server.
        required: false
        default: disabled
        choices:
        - localFirst
        - disabled
      local_user_fallback:
        description:
          - Specifies whether to enable TACACS+ secure backdoor for Telnet.
        required: false
        default: disabled
        choices:
        - localFirst
        - disabled
      command_authorization:
        description:
          - Specifies whether to enable TACACS+ command authorization.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      command_logging:
        description:
          - Specifies whether to enable TACACS+ command logging.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      privilege_level_mapping:
        description:
          - Specifies whether to enable TACACS+ new privilege level mapping.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      command_logging_type:
        description:
          - Specifies command logging type.
        required: false
        default: null
        choices:
        - admin
        - accounting
      otp:
        description:
          - Enable/Disable OTP.
        required: false
        default: null
        choices:
        - enabled
        - disabled
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_system_tacacs_auth:
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
      state: enabled
      port: 49
      primary_ip4_address: 10.10.1.1
      secondary_ip4_address: 10.10.1.2
      timeout_second: 10
      retries: 2
      primary_secret: secret
      secondary_secret: secret
      local_user_priority: localFirst
      local_user_fallback: enabled
      otp: disabled
      command_authorization: enabled
      privilege_level_mapping: enabled
      command_logging_type: accounting
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
from radware.alteon.sdk.configurators.system_tacacs_authentication import SystemTacacsAuthenticationConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SystemTacacsAuthenticationConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SystemTacacsAuthenticationConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

