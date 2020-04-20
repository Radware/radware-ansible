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
module: alteon_config_static_routes
short_description: Manage static routes in Radware Alteon
description:
  -  Manage static routes in Radware Alteon.
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
      - Parameters for static routes configuration.
    suboptions:
      ip4_routes:
        description:
          - IPv4 routes.
        required: false
        default: null
        type: list
        elements:
          network:
            description:
              - The destination IP address of this route.
            required: true
            default: null
            type: str
          subnet:
            description:
              - The subnet mask of this route.
            required: true
            default: null
            type: str
          gateway:
            description:
              - The IP address of the destination gateway for this route.
            required: true
            default: null
            type: str
          interface:
            description:
              - The IP interface of this route. Alteon uses the IP address of the specified interface as the source IP address when doing the routing.
            required: false
            default: null
            type: int
      ip6_routes:
        description:
          - IPv6 routes.
        required: false
        default: null
        type: list
        elements:
          network:
            description:
              - The destination IP address of this route.
            required: true
            default: null
            type: str
          prefix:
            description:
              - The prefix length associated with this IP address.
            required: true
            default: null
            type: int
          gateway:
            description:
              - The IP address of the destination gateway for this route.
            required: true
            default: null
            type: str
          vlan:
            description:
              - The VLAN of this route. Alteon uses the IP address of the specified VLAN as the source IP address when doing the routing.
            required: false
            default: null
            type: int
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_static_routes:
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
      ip4_routes:
        - network: 6.6.6.0
          subnet: 255.255.255.0
          gateway: 1.1.1.254
          interface: 2
        - network: 7.7.7.0
          subnet: 255.255.255.0
          gateway: 1.1.1.254
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
from radware.alteon.sdk.configurators.l3_static_routes import StaticRoutesConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(StaticRoutesConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(StaticRoutesConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

