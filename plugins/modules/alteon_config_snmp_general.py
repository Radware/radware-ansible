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
module: alteon_config_snmp_general
short_description: Manage SNMP general parameters in Radware Alteon
description:
  - configure SNMP general parameters in Radware Alteon. 
version_added: '2.9'
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
      - When C(absent), when applicable removes the object. Not supported in this module.
      - When C(read), when exists read object from configuration to parameter format.
      - When C(overwrite), removes the object if exists then recreate it. Not supported in this module.
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
      - SNMP general parameters configuration.
    suboptions:
      snmp_access:
        description:
          - Set SNMP access control.
        required: false
        default: disabled
        choices:
        - read_only
        - read_write
        - disabled
      snmp_v1v2_access:
        description:
          - Enable/disable V1/V2 access.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      sys_name:
        description:
          - Set SNMP sysName
        required: false
        default: null
        type: str
      sys_location:
        description:
          - Set SNMP sysLocation.
        required: false
        default: null
        type: str
      sys_contact:
        description:
          - Set SNMP sysLocation.
        required: false
        default: null
        type: str
      snmp_read_comm:
        description:
          - Set SNMP read community string.
        required: false
        default: null
        type: str
      snmp_write_comm:
        description:
          - Set SNMP write community string.
        required: false
        default: null
        type: str
      trap_src_if:
        description:
          - Set SNMP trap source interface.
        required: false
        default: null
        type: int
      snmp_timeout:
        description:
          - Set timeout for the SNMP state machine.
        required: false
        default: null
        type: int
      snmp_trap1_ipv6_addr:
        description:
          - Set first SNMP trap host address (ipv6).
        required: false
        default: null
        type: str
      snmp_trap1:
        description:
          - Set Set first SNMP trap host address (ipv4)
        required: false
        default: null
        type: str
      snmp_trap2_ipv6_addr:
        description:
          - Set Set second SNMP trap host address (ipv6)
        required: false
        default: null
        type: str
      snmp_trap2:
        description:
          - Set Set seond SNMP trap host address (ipv4)
        required: false
        default: null
        type: str
      auth_ena_traps:
        description:
          - Enable/disable SNMP sysAuthenTrap.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_snmp_general:
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
      auth_ena_traps: enabled
      snmp_access: read_write
      snmp_read_comm: public
      snmp_timeout: 5
      snmp_trap1: 1.1.1.1
      snmp_trap1_ipv6_addr: null
      snmp_trap2: 2.2.2.2
      snmp_trap2_ipv6_addr: null
      snmp_v1v2_access: enabled
      snmp_write_comm: private
      sys_contact: contact
      sys_location: location
      sys_name: name
      trap_src_if: 1
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
from radware.alteon.sdk.configurators.snmp_general import SnmpGeneralConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SnmpGeneralConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SnmpGeneralConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
