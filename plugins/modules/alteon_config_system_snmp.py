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
module: alteon_config_system_snmp
short_description: Manage SNMP in Radware Alteon
description:
  - Manage SNMP in Radware Alteon.
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
      - Parameters for SNMP configuration.
    suboptions:
      snmp_access_level:
        description:
          - The SNMP access control.
        required: false
        default: null
        choices:
        - read_only
        - read_write
        - disabled
      snmp_v1_v2_state:
        description:
          - Specifies whether to enable V1/V2 access.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      read_community:
        description:
          - The SNMP Read community string.
        required: false
        default: null
        type: str
      write_community:
        description:
          - The SNMP Write community string.
        required: false
        default: null
        type: str
      trap_source_interface:
        description:
          - The SNMP trap source interface number.
        required: false
        default: null
        type: int
      trap_ip4_host1:
        description:
          - The first SNMP trap host IP address.
        required: false
        default: null
        type: str
      trap_ip4_host2:
        description:
          - The second SNMP trap host IP address.
        required: false
        default: null
        type: str
      trap_ip6_host1:
        description:
          - The first SNMP trap host IP address.
        required: false
        default: null
        type: str
      trap_ip6_host2:
        description:
          - The second SNMP trap host IP address.
        required: false
        default: null
        type: str
      authentication_failure_traps:
        description:
          - Specifies whether the SNMP entity is permitted to generate authenticationFailure traps. The value of this object overrides any configuration information. As such, it provides a means whereby all authenticationFailure traps may be disabled.
          - Note that it is strongly recommended that this object be stored in non-volatile memory so that it remains constant across re-initializations of the network management system.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      system_name:
        description:
          - An assigned name for this managed node. By convention, this is the node fully-qualified domain name. If the name is unknown, the value is the zero-length string.
        required: false
        default: null
        type: str
      system_location:
        description:
          - The physical location of this node (for example, 'telephone closet 3rd floor'). If the location is unknown, the value is the zero-length string.
        required: false
        default: null
        type: str
      system_contact:
        description:
          - The textual identification of the contact person for this managed node together with information on how to contact this person. If no contact information is known, the value is the zero-length string.
        required: false
        default: disabled
        type: str
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_system_snmp:
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
      snmp_access_level: read_write
      snmp_v1_v2_state: enabled
      read_community: public
      write_community: private
      trap_ip4_host1: 10.10.10.1
      authentication_failure_traps: enabled
      system_name: alt.test
      system_location: ny
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
from radware.alteon.sdk.configurators.system_snmp import SystemSNMPConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SystemSNMPConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SystemSNMPConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

