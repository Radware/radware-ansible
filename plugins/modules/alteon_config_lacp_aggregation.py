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
module: alteon_config_lacp_aggregation
short_description: Manage lacp aggregation in Radware Alteon
description:
  - Manage lacp aggregation in Radware Alteon.
  - This feature is available only in Alteon standalone, VA, and ADC-VX mode.
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
      - Parameters for lacp aggregation configuration.
    suboptions:
      lacp_system_name:
        description:
          - The name of the LACP group.
        required: false
        default: null
        type: str
      timeout_mode:
        description:
          - The size of the timeout. If a port does not receive LACPDUs before the timeout expires, Alteon invalidates LACP information pertaining to the port.
          - Choose short for 3 seconds or long for 90 seconds.
        required: false
        default: null
        choices:
        - short
        - long
      block_port_outside_of_aggr:
        description:
          - Specifies what to do with traffic on a port (whether to block or to forward) that is not in a Link Aggregation Group.
        required: false
        default: null
        default: null
        choices:
        - enabled
        - disabled
      system_priority:
        description:
          - A read-write value indicating the priority value associated with the Actor's System ID.
        required: false
        default: null
        type: int
      groups:
        description:
          - LACP group.
        required: false
        default: null
        type: list
        elements:
          id:
            description:
              - The LACP port ID.
            required: true
            default: null
            type: int
          state:
            description:
              - LACP State.
              - Choose off to turn off LACP on port.
              - Choose active to initiate LACPDU updates on port.
              - Choose passive to not initiate LACPDU updates but responds to peer.
            required: true
            default: null
            choices:
            - off
            - active
            - passive
          ports:
            description:
              - Port IDs.
            required: true
            default: null
            type: list
            elements: int
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_lacp_aggregation:
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
      lacp_system_name: lacp_sys_name
      timeout_mode: short
      block_port_outside_of_aggr: enabled
      groups:
        - id: 50
          state: active
          ports:
            - 2
            - 3
        - id: 100
          state: passive
          ports:
            - 8
            - 9      
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
from radware.alteon.sdk.configurators.lacp_aggregation import LACPAggregationConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(LACPAggregationConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(LACPAggregationConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

