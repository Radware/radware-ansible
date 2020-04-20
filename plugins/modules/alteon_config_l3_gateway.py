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
module: alteon_config_l3_gateway
short_description: Manage l3 gateway in Radware Alteon
description:
  - Manage l3 gateway in Radware Alteon. 
  - Alteon can be configured with up to 255 gateways.
  - Gateways 1 to 4 are reserved for default gateway load balancing. Gateways 5 to 259 are used for load-balancing of VLAN-based gateways.
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
      - Parameters for l3 gateway configuration.
    suboptions:
      index:
        description:
          - Gateway index.
        required: true
        default: null
        type: int
      state:
        description:
          - Gateway state.
        required: true
        default: null
        choices:
        - enabled
        - disabled
      ip_ver:
        description:
          - IP version.
        required: false
        default: null
        choices:
        - ipv4
        - ipv6
      ip4_address:
        description:
          - IPv4 address.
        required: false
        default: null
        type: str
      ip6_address:
        description:
          - IPv6 address.
        required: false
        default: null
        type: str
      vlan:
        description:
          - VLAN ID.
        required: false
        default: null
        type: int
      health_check_type:
        description:
          - Gateway health check type.
        required: false
        default: icmp
        choices:
        - arp
        - icmp
      health_check_interval_second:
        description:
          - The interval, in seconds, between heakth check attempts.
        required: false
        default: 2
        type: int
      health_check_retries:
        description:
          - The number of failed attempts to declare the default gateway DOWN.
        required: false
        default: 8
        type: int
      route_priority:
        description:
          - The priority of the default route for this gateway.
          - High priority means that the default gateway route will have higher priority over learned default routes.
          - Low priority means that the default gateway route will have lower priority than learned default routes.
        required: false
        default: null
        choices:
        - low
        - high
      global_gateway_metric:
        description:
          - Set gateway metric
          - In strict the gateway number determines its level of preference. Gateway 1 acts as the preferred default IP gateway until it fails or is disabled, at which, point the next in line takes over as the default IP gateway.
          - roundrobin is basic gateway load balancing. Alteon sends each new gateway request to the next healthy, enabled gateway in line. All gateway requests to the same destination IP address are resolved to the same gateway.
        required: false
        default: null
        choices:
        - strict
        - roundrobin
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_l3_gateway:
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
      index: 6
      state: enabled
      ip4_address: 1.1.1.254
      ip_ver: ipv4
      vlan: 10
      health_check_type: icmp
      health_check_interval_second: 30
      health_check_retries: 3
      route_priority: high
      global_gateway_metric: roundrobin              
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
from radware.alteon.sdk.configurators.l3_gateway import GatewayConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(GatewayConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(GatewayConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
