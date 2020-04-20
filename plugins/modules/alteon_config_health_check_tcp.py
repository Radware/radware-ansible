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
module: alteon_config_health_check_tcp
short_description: Manage tcp health check in Radware Alteon
description:
  - Manage tcp health checks in Radware Alteon 
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
      - Parameters for TCP health check configuration.
    suboptions:
      index:
        description:
          - TCP health check ID.
        required: true
        default: null
        type: str
      description:
        description:
          - Set descriptive health check name.
        required: false
        default: null
        type: str
      destination_port:
        description:
          - Set desination port.
          - Set value to none in order to take this value from rport or the bound element.
        required: false
        default: null
        type: str
      ip_ver:
        description:
          - Set destination IP version.
          - Choose none to inherit from real server.
        required: false
        default: none
        choices:
        - ipv4
        - ipv6
        - none
      destination_ip_or_hostname:
        description:
          - Set destination IP address or hostname.
          - This parameter required only when the IP Version is IPv4 or IPv6.
        required: false
        default: none
        type: str
      transparent_health_check:
        description:
          - Enable/disable transparent health check.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      interval_second:
        description:
          - Set time, in seconds, between keep-alive attempts.
        required: false
        default: 5
        type: int
      retries_failure:
        description:
          - Set the number of failed attempts to declare a server down.
        required: false
        default: 4
        type: int
      retries_restore:
        description:
          - Set the number of successful attempts to declare a server up.
        required: false
        default: 2
        type: int
      response_timeout_second:
        description:
          - Set the time, in seconds, to wait for response. This value must be lower or equal to the Interval parameter.
        required: false
        default: 5
        type: int
      interval_downtime_second:
        description:
          - Set the time, in seconds, between health checks when a server is down.
        required: false
        default: 0
        type: int
      invert_result:
        description:
          - Set whether to invert of expected result.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      connection_termination:
        description:
          - Set connection termination.
          - Value for the tcphalfopen out-of-the-box health check: RST.
        required: false
        default: fin
        choices:
        - fin
        - rst
      standalone_real_hc_mode:
        description:
          - Perform health check for real servers that are not attached to any virtual service or filter.
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
  alteon_config_health_check_tcp:
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
      index: tcp_80
      description: tcp_80
      ip_ver: ipv4
      destination_ip_or_hostname: 1.1.1.1
      connection_termination: rst
      destination_port: 80
      interval_second: 8
      interval_downtime_second: 4       
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
from radware.alteon.sdk.configurators.health_check_tcp import HealthCheckTCPConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(HealthCheckTCPConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(HealthCheckTCPConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
