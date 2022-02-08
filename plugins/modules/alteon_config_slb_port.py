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
module: alteon_config_slb_port
short_description: Manage SLB port parameters in Radware Alteon
description:
  - Manage SLB port parameters in Radware Alteon.
version_added: '2.9'
author: 
  - Ofer Epstein (@ofere)
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
      - Parameters for SLB port configuration.
    suboptions:
      index:
        description:
          - SLB port index.
        required: true
        default: null
        type: str
      state:
        description:
          - SLB state of the port.
        required: false
        default: null
        choices:
        - none
        - client
        - server
        - client-server
      hot_standby:
        description:
          - Enable or disable hot standby processing on the switch port.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      inter_switch:
        description:
          - Enable or disable inter-switch processing on the switch port.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      pip_state:
        description:
          - Enable or disable use of proxy IP address on the switch port.
        required: true
        default: null
        choices:
        - enabled
        - disabled
      rts_state:
        description:
          - Enable or disable RTS processing on the switch port.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      delete:
        description:
          - delete raw.
        required: false
        default: null
        choices:
        - other
        - delete
      idslb_state:
        description:
          - Enable or disable Intrusion Detection server load balancing.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      filter:
        description:
          - Enable or disable Filtering.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      add_filter:
        description:
          - Specify the Filter Number to be added to this Port table.
        required: false
        default: null
        choices:
        - 1-2048
      rem_filter:
        description:
          - Specify the Filter Number to be deleted from this Port table.
        required: false
        default: null
        choices:
        - 1-2048
      server_state:
        description:
          - Enable or disable Server Processing.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      client_state:
        description:
          - Enable or disable Client Processing.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      l3_filter:
        description:
          - Enable or disable Layer3 Filtering.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      filter_bmap:
        description:
          - The filtering rules applied to the port (read-only).
        required: false
        default: null
        type: str
      vlan_bmap:
        description:
          - VLANs associated with this port (read-only).
        required: false
        default: null
        type: str
      inter_switch_vlan:
        description:
          - VLAN for inter-switch processing.
        required: false
        default: null
        choices:
        - 1-4090
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_slb_port:
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
      index: 1
      state: client
      hot_standby: disabled
      inter_switch: disabled
      pip_state: disabled
      rts_state: disabled
      delete: other
      idslb_state: disabled
      filter: disabled
      add_filter: 1
      rem_filter: 1
      server_state: disabled
      client_state: disabled
      l3_filter: disabled
      filter_bmap: 1 2
      inter_switch_vlan: 1
      vlan_bmap: 1 2
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
from radware.alteon.sdk.configurators.slb_port import SlbPortConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SlbPortConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SlbPortConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

