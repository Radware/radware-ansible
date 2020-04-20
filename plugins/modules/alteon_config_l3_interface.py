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
module: alteon_config_l3_interface
short_description: Manage l3 interface in Radware Alteon
description:
  - Alteon needs an IP interface for each subnet to which it is connected so it can communicate with the real servers and other devices attached to it that receive switching services. 
  - Alteon can be configured with up to 256 IP interfaces. Each IP interface represents Alteon on an IP subnet on your network.
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
      - Parameters for l3 interafce configuration.
    suboptions:
      index:
        description:
          - Interface ID.
        required: true
        default: null
        type: int
      description:
        description:
          - Interface description.
        required: false
        default: null
        type: str
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
      vlan:
        description:
          - VLAN ID.
        required: false
        default: null
        type: int
      state:
        description:
          - Gateway state.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      bootp_relay:
        description:
          - Specifies whether to enable BOOTP relay.
          - In the DHCP environment, Alteon acts as a relay agent. 
          - This BOOTP relay feature enables Alteon to forward a client request for an IP address to two BOOTP servers with configured IP addresses.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      ip_ver:
        description:
          - IP version.
        required: false
        default: ipv4
        choices:
        - ipv4
        - ipv6
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
      peer_ip:
        description:
          - The peer interface IP address used in high availability unicast session failover.
          - Radware recommends that you configure a peer IP address for all IP interfaces participating in session failover.
        required: false
        default: null
        type: str
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
      index: 10
      state: enabled
      ip4_address: 8.8.8.8
      ip_ver: ipv4
      vlan: 10
      bootp_relay: enabled
      peer_ip: 8.8.8.9          
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
from radware.alteon.sdk.configurators.l3_interface import L3InterfaceConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(L3InterfaceConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(L3InterfaceConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
