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
module: alteon_config_virtual_server
short_description: Manage virtual server in Radware Alteon
description:
  - Manage virtual server in Radware Alteon.
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
      - Parameters for virtual server configuration.
    suboptions:
      index:
        description:
          - Specifies the identifier of the virtual server.
          - Alteon uses the name and the application as the identifier for all objects created for this service (group, SSL policy, FastView policy).
        required: true
        default: null
        type: str
      ip_ver:
        description:
          - Specifies the type of IP address for the virtual server.
        required: false
        default: ipv4
        choices:
        - ipv4
        - ipv6
      ip_address:
        description:
          - Specifies the IP version and address of the virtual server. The virtual server created within Alteon responds to ARPs and pings from network ports as if it was a normal server.
          - Client requests directed to the virtual server IP address are balanced among the real servers available to it through real server group assignments.
        required: false
        default: null
        type: str
      ip6_address:
        description:
          - Specifies the IP version and address of the virtual server. The virtual server created within Alteon responds to ARPs and pings from network ports as if it was a normal server.
          - Client requests directed to the virtual server IP address are balanced among the real servers available to it through real server group assignments.
        required: false
        default: null
        type: str
      state:
        description:
          - Specifies whether to enable the virtual server. This option activates the virtual server so that it can service client requests sent to its defined IP address.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      domain_name:
        description:
          - Specifies the domain name for this virtual server. When configured the domain name is used for:
          - DNS resolution for global load balancing. Additional domains can be defined on the same virtual server by attaching multiple DNS (GSLB) rules, each with a different domain.
          - HTTP/S health check, if the health check Host parameter is set to Inherit.
          -
          - The domain name typically includes the name of the company or organization, and the Internet group code (.com, .edu, .gov, .org, and so on). For example, 'foocorp.com'.
          - It does not include the hostname portion (www, www2, ftp, and so on).
        required: false
        default: null
        type: str
      weight:
        description:
          - Specifies the global server weight for the virtual server.
          - The higher the weight value, the more connections that are directed to the local site.
        required: false
        default: 1
        type: int
      availability:
        description:
          - Specifies the Global Server Load Balancing (GSLB) priority for the virtual server.
          - Rules that use Availability as the primary metric handle failures by selecting the server with the next highest score compared to that of the server that failed, and begin forwarding requests to that server. If the server that failed becomes operational again, that server regains precedence and requests are routed to it once more.
        required: false
        default: 1
        type: int
      virtual_server_name:
        description:
          - Specifies a descriptive name for the virtual server.
        required: false
        default: null
        type: str
      connection_rst_invalid_port:
        description:
          - Specifies whether to drop or reset connections to an invalid virtual port.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      src_network_class_id:
        description:
          - Specifies the network class that defines the clients to which this virtual server provides service. Defining a source network per virtual server allows you to provide differentiated services for the same application to different clients or departments.
        required: false
        default: null
        type: str
      availability_persist:
        description:
          - Specifies whether a server that failed and became operational again, can (Disable) or cannot (Enable) regain precedence from the recovery server.
          - Ensuring that the former primary server does not regain precedence is achieved by assigning the highest possible availability value (48) to the server that takes over after a failure. If this new primary server fails, its original availability value is restored and the next server in the list gains the higher precedence.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      wan_link_id:
        description:
          - Specifies the WAN Link via which this virtual server can be accessed, when the application can be accessed via multiple WAN links (multihoming).
        required: false
        default: null
        type: str
      return_to_src_mac:
        description:
          - Specifies how to forward response traffic to the client.
          - C(enabled)-Alteon returns the response traffic to the MAC address from which the request arrived, bypassing all routing configuration in the device.
          - C(disabled)-Alteon returns the traffic using the routing table.
        required: false
        default: disabled
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
  alteon_config_virtual_server:
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
      index: virt_test
      state: enabled
      ip_address: 56.56.56.56
      domain_name: test.com
      weight: 6
      availability: 10
      availability_persist: enabled
      connection_rst_invalid_port: enabled
      return_to_src_mac: enabled
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
from radware.alteon.sdk.configurators.virtual_server import VirtualServerConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(VirtualServerConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(VirtualServerConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
