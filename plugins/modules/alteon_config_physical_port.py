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
module: alteon_config_physical_port
short_description: Manage physical port in Radware Alteon
description:
  - Manage physical port in Radware Alteon
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
      - Parameters for physical interface configuration.
    suboptions:
      index:
        description:
          - Port ID.
        required: true
        default: null
        type: int
      state:
        description:
          - Port state.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      vlan_tag_mode:
        description:
          - VLAN tag state of the port.
        required: false
        default: null
        choices:
        - tagged
        - untagged
      rmon_state:
        description:
          - Specifies whether to enable RMON on the port.
        required: false
        default: off
        choices:
        - on
        - off
      pvid:
        description:
          - The default VLAN ID for the port.
        required: false
        default: 1
        type: int
      name:
        description:
          - The switch port name.
        required: false
        default: null
        type: str
      traffic_contract_id:
        description:
          - The switch port Bandwidth Management contract number.
        required: false
        default: 1024
        type: int
      discard_non_ip_traffic:
        description:
          - Discard non-IP traffic on port.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      link_state_trap:
        description:
          - Specifies whether linkUp/linkDown traps are generated for this interface.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      port_alias:
        description:
          - The switch port alias.
        required: false
        default: null
        type: str
      spanning_tree_state:
        description:
          - Specifies whether to enable the spanning tree.
        required: false
        default: null
        choices:
        - on
        - off
      ip_forwarding:
        description:
          - IP forwarding is enabled by default and is used for VLAN-to-VLAN (non-BGP) routing. 
          - Make sure IP forwarding is enabled if the default gateways are on different subnets or if Alteon is connected to different subnets and those subnets need to communicate through Alteon.
          - Specifies whether to enable IP forwarding.
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
  alteon_config_physical_port:
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
      index: 2
      state: enabled
      vlan_tag_mode: tagged
      pvid: 10
      name: my_port
      discard_non_ip_traffic: enabled
      link_state_trap: enabled
      spanning_tree_state: on
      ip_forwarding: enabled      
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
from radware.alteon.sdk.configurators.physical_port import PhysicalPortConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(PhysicalPortConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(PhysicalPortConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
