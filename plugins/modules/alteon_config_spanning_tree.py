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
module: alteon_config_spanning_tree
short_description: Manage spanning tree in Radware Alteon
description:
  - Manage spanning tree in Radware Alteon
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
      - Parameters for spanning tree configuration.
    suboptions:
      state:
        description:
          - Spanning tree state.
        required: true
        default: null
        choices:
        - on
        - off
      mstp:
        description:
          - Enable/Disable Multiple Spanning Tree
        required: false
        default: null
        choices:
        - enabled
        - disabled
      mstp_mode:
        description:
          - The mode of the spanning tree.
        required: false
        default: null
        choices:
        - mstp
        - rstp
      mstp_region_name:
        description:
          - A name for the region.
        required: false
        default: null
        type: str
      mstp_region_version:
        description:
          - The region version.
        required: false
        default: null
        type: int
      mstp_maximum_hops:
        description:
          - The maximum number of hops.
        required: false
        default: null
        type: int
      mstp_bridge_priority:
        description:
          - The value of the writable portion of the Bridge Identifier comprising of the first two octets.
        required: false
        default: null
        type: int
      mstp_bridge_max_age_second:
        description:
          - The time, in seconds, that all bridges use for MaxAge when this bridge is acting as the root.
        required: false
        default: null
        type: int
      mstp_bridge_forward_delay_second:
        description:
          - The time, in seconds, that all bridges use for ForwardDelay when this bridge is acting as the root.
        required: false
        default: null
        type: int
      stp_groups:
        description:
          - Spanning tree group parameters.
        required: false
        default: null
        type: list
        elements:
          id:
            description:
              - The identifier of this spanning tree group.
            required: true
            default: null
            type: int
          state:
            description:
              - Spanning tree state.
            required: false
            default: null
            choices:
            - on
            - off
          bridge_priority:
            description:
              - The value of the writeable portion of the Bridge ID - that is, the first two octets of the (8 octet long) Bridge ID.
            required: false
            default: 32768
            type: int
          bridge_hello_time_second:
            description:
              - The time, in seconds, that all bridges use for HelloTime when this bridge is acting as the root.
            required: false
            default: 2
            type: int
          bridge_max_age_second:
            description:
              - The time, in seconds, that all bridges use for MaxAge when this bridge is acting as the root.
            required: false
            default: 20
            type: int
          bridge_forward_delay_second:
            description:
              - The time, in seconds, that all bridges use for ForwardDelay when this bridge is acting as the root.
            required: false
            default: 15
            type: int
          bridge_aging_time_second:
            description:
              - The timeout period, in seconds, for aging out dynamically learned forwarding information.
              - 0 is to disable.
            required: false
            default: 300
            type: int
          pvst_frames_on_untagged_ports:
            description:
              - Specifies whether Alteon sends Cisco Per VLAN Spanning Tree (PVST+) protocol frames on untagged ports.
            required: false
            default: null
            choices:
            - enabled
            - disabled
          pvst_frames_on_untagged_ports:
            description:
              - Specifies the VLANs in the spanning tree group.
            required: false
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
  alteon_config_spanning_tree:
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
      state: on
      mstp: enabled
      mstp_mode: mstp
      mstp_region_version: 3
      mstp_maximum_hops: 10
      stp_groups:
        - id: 1
          state: on
          bridge_hello_time_second: 10
          pvst_frames_on_untagged_ports: enabled
          vlans:
            - 1
            - 10
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
from radware.alteon.sdk.configurators.spanning_tree import SpanningTreeConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SpanningTreeConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SpanningTreeConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

