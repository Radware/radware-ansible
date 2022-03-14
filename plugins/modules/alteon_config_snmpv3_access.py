#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, Radware LTD. 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: alteon_config_snmpv3_access
short_description: Manage SNMPv3 access in Radware Alteon
description:
  - Manage SNMPv3 access in Radware Alteon.
version_added: '2.9'
author: 
  - Michal Greenberg (@michalg)
options:
  provider:
    description:
      - Radware Alteon connection details.
    required: true
    suboptions:
      server:
        description:
          - Radware Alteon IP address.
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
      - Parameters for SNMPv3 group configuration.
    suboptions:
      group_name:
        description:
          - The name of the group to which this entry belongs.
        required: true
        default: null
        type: str
      context_prefix:
        description:
          - The value that must match to gain the access rights allowed by this row.
          - This field is a key and must be set. If you want it to be empty, you should set " ".
        required: true
        default: null
        type: str
      security_model:
        description:
          - Set the security model.
        required: true
        default: null
        choices:
        - SNMPV1
        - SNMPV2c
        - UserBased
      security_level:
        description:
          - The minimum level of security required to gain the access rights allowed by this row.
        required: true
        default: null
        choices:
        - NoAuthNoPriv
        - AuthNoPriv
        - AuthAndPriv
      match_type:
        description:
          - Set access match.
        required: false
        default: null
        choices:
        - Exact
        - Prefix
      read_view_name:
        description:
          - The MIB view of the SNMP context to which this row authorizes read access. 
        required: false
        default: null
        type: str
      write_view_name:
        description:
          - The MIB view of the SNMP context to which this row authorizes write access.
        required: false
        default: null
        type: str
      notify_view_name:
        description:
          - The MIB view of the SNMP context to which this row authorizes access for notifications.
        required: false
        default: null
        type: str
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_snmpv3_access:
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
      group_name: testgrp
      context_prefix: " "
      security_model: UserBased   
      security_level: AuthAndPriv   
      read_view_name: iso
      write_view_name: iso
      notify_view_name: iso
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

from ansible_collections.radware.radware_modules.plugins.module_utils.common import RadwareModuleError
from ansible_collections.radware.radware_modules.plugins.module_utils.alteon import AlteonConfigurationModule, \
    AlteonConfigurationArgumentSpec as ArgumentSpec
from radware.alteon.sdk.configurators.snmpv3_access import SNMPv3AcessConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SNMPv3AcessConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SNMPv3AcessConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

