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
module: alteon_config_server
short_description: Manage real server in Radware Alteon
description:
  - Manage real server in Radware Alteon
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
      - Parameters for real server configuration.
    suboptions:
      index:
        description:
          - Real server ID.
        required: true
        default: null
        type: str
      state:
        description:
          - Real server state.
        required: false
        default: null
        choices:
        - enabled
        - disabled
        - disabled_with_fastage
        - shutdown_connection
        - shutdown_persistent_sessions
      ip_ver:
        description:
          - Specifies the type of IP address.
        required: false
        default: ipv4
        choices:
        - ipv4
        - ipv6
      ip_address:
        description:
          - The IPv4 address of the real server.
        required: false
        default: null
        type: str
      ip6_address:
        description:
          - The IPv6 address of the real server.
        required: false
        default: null
        type: str
      weight:
        description:
          - The server weight.
        required: false
        default: 1
        type: int
      max_connections:
        description:
          - Specifies the maximum number of simultaneous connections that this real server can support.
          - No new connections are issued to this server if this limit is reached. New connections are issued again to this server once the number of current connections has decreased below the limit.
          - 0 means no connection limit
        required: false
        default: 0
        type: int
      connection_mode:
        description:
          - Specifies the maximum connections mode.
          - Real servers with the same IP address must be configured with the same maximum connections mode.
          - In C(physical), real servers with the same IP address configured with the physical maximum connections mode must all have the same Maximum Connections value.
          - In C(logical), real servers with the same IP address configured with the logical maximum connections mode can each have a different Maximum Connections value.
        required: false
        default: physical
        choices:
        - physical
        - logical
      availability:
        description:
          - The weight of the server when performing the Global Server Load Balancing (GSLB) decision using the availability metric.
        required: false
        default: null
        type: int
      server_type:
        description:
          - The server type. It participates in global Server Load Balancing when it is configured as remote-server.
        required: false
        default: local_server
        choices:
        - local_server
        - remote_server
      nat_mode:
        description:
          - Specifies Client NAT configuration source.
        required: false
        default: enable
        choices:
        - enable
        - address
        - nwclss
        - disable
      nat_address:
        description:
          - The Client NAT address for the real server.
        required: false
        default: null
        type: str
      nat_subnet:
        description:
          - The subnet mask for the Client NAT address for the real server.
        required: false
        default: null
        type: str
      nat6_address:
        description:
          - The Client NAT IPv6 address for the real server.
        required: false
        default: null
        type: str
      nat6_prefix:
        description:
          - The prefix for the Client NAT address for the real server.
        required: false
        default: null
        type: int
      nat_ip_persistency:
        description:
          - Client NAT Persistency when persistency mode is address or subnet.
        required: false
        default: disable
        choices:
        - disable
        - client
        - host
      nat_network_class_name:
        description:
          - NAT network class name.
        required: false
        default: null
        type: str
      nat_net_class_ip_persistency:
        description:
          - Client NAT Persistency when persistency mode is network class.
        required: false
        default: disable
        choices:
        - disable
        - client
      health_check_id:
        description:
          - Health check ID.
        required: false
        default: null
        type: str
      server_ports:
        description:
          - The Layer 4 real-service port number.
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
  alteon_config_server:
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
      index: real1
      state: disabled_with_fastage
      ip_address: 80.80.80.80
      weight: 7
      availability: 5
      health_check_id: hc_test
      server_ports:
        - 80
        - 8080
        - 8081
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
from radware.alteon.sdk.configurators.server import ServerConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(ServerConfigurator, **kwargs)


def main():

    spec = ArgumentSpec(ServerConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)
    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
