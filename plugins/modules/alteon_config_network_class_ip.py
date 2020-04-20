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
module: alteon_config_network_class_ip
short_description: Manage network class in Radware Alteon
description:
  - You can set a network class to include several subnets or IP ranges, which can be used for filtering and virtual server classification.
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
      - Parameters for network class configuration.
    suboptions:
      index:
        description:
          - Network class ID.
        required: true
        default: null
        type: str
      ip_ver:
        description:
          - IP version.
        required: false
        default: ipv4
        choices:
        - ipv4
        - ipv6
      description:
        description:
          - Network class description.
        required: false
        default: null
        type: str
      classes:
        description:
          - Network class elements.
        required: false
        default: null
        type: list
        elements:
          name:
            description:
              - The ID of the network class element.
            required: true
            default: null
            type: int
          network_type:
            description:
              - Specifies the type of network class element.
            required: true
            default: subnet
            choices:
            - subnet
            - range
          ip4_address:
            description:
              - IPv4 address.
            required: false
            default: null
            type: str
          ip4_subnet:
            description:
              - IPv4 subnet mask.
            required: false
            default: null
            type: str
          ip4_range_first_address:
            description:
              - The first IP address in the range.
            required: false
            default: null
            type: str
          ip4_range_last_address:
            description:
              - The last IP address in the range.
            required: false
            default: null
            type: str
          ip6_address:
            description:
              - IPv6 address.
            required: false
            default: null
            type: str
          ip6_prefix:
            description:
              - IPv6 prefix.
            required: false
            default: null
            type: str
          ip6_range_first_address:
            description:
              -The first IP address in the range.
            required: false
            default: null
            type: str
          ip6_range_last_address:
            description:
              - The last IP address in the range.
            required: false
            default: null
            type: str
          match_type:
            description:
              - Include/Exclude the IP addresses that match the element definition in the network class.
            required: false
            default: include
            choices:
            - include
            - exclude
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_l3_interface:
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
      index: net_class_ip_test
      description: test
      ip_ver: ipv4
      classes:
        - name: net_1
          network_type: subnet
          ip4_address: 172.16.5.0
          ip4_subnet: 255.255.255.0
          match_type: exclude
        - name: net_2
          network_type: range
          ip4_range_first_address: 172.16.6.1
          ip4_range_last_address: 172.16.6.15
          match_type: include
        - name: net_3
          network_type: range
          ip4_range_first_address: 172.16.0.1
          ip4_range_last_address: 172.16.0.15
          match_type: include     
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
from radware.alteon.sdk.configurators.network_class_ip import NetworkClassIPConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(NetworkClassIPConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(NetworkClassIPConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

