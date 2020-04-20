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
module: alteon_config_health_check_http
short_description: Manage HTTP health check in Radware Alteon
description:
  - Manage HTTP health check in Radware Alteon 
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
      - Parameters for HTTP health check configuration.
    suboptions:
      index:
        description:
          - Health check ID.
        required: true
        default: null
        type: str
      description:
        description:
          - Descriptive health check name.
        required: false
        default: null
        type: str
      destination_port:
        description:
          - Application port.
        required: false
        default: null
        type: int
      ip_ver:
        description:
          - Destination IP address version.
        required: false
        default: null
        choices:
        - ipv4
        - ipv6
        - none
      destination_ip_or_hostname:
        description:
          -Destination address or hostname.
        required: false
        default: null
        type: str
      transparent_health_check:
        description:
          - Enable/disable transparent health check.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      interval_second:
        description:
          - Interval between health checks in seconds.
        required: false
        default: null
        type: int
      retries_failure:
        description:
          - Number of failed attempts to declare server down.
        required: false
        default: null
        type: int
      retries_restore:
        description:
          - Number of successful attempts to declare server up.
        required: false
        default: null
        type: int
      response_timeout_second:
        description:
          - Max seconds to wait for response.
        required: false
        default: null
        type: int
      interval_downtime_second:
        description:
          - Interval between health checks when server is down.
        required: false
        default: null
        type: int
      invert_result:
        description:
          - Enable/disable invert of expected result.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      connection_termination:
        description:
          - Set connection termination.
        required: false
        default: null
        choices:
        - fin
        - rst
      standalone_real_hc_mode:
        description:
          - Enable/disable always performing the health check.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      https:
        description:
          - Enable/disable SSL for HTTPS Health check.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      http_hostname:
        description:
          - Set host header.
        required: false
        default: null
        type: str
      http_path:
        description:
          - Set request path.
        required: false
        default: null
        type: str
      http_method:
        description:
          - Set HTTP method.
        required: false
        default: null
        choices:
        - get
        - post
        - head
      http_headers_raw:
        description:
          - Set request header.
        required: false
        default: null
        type: str
      http_body:
        description:
          - Set request body.
        required: false
        default: null
        type: str
      authentication:
        description:
          - Set authentication.
        required: false
        default: null
        choices:
        - none
        - basic
        - ntlm2
        - ntlmssp
      auth_username:
        description:
          - Set authentication username.
        required: false
        default: null
        type: str
      auth_password:
        description:
          - Set authentication password.
        required: false
        default: null
        type: str
      return_string_lookup_type:
        description:
          - Set response string lookup type.
        required: false
        default: null
        choices:
        - none
        - incl
        - excl
      overload_string_lookup_type:
        description:
          - Set expected response for server overload.
        required: false
        default: null
        choices:
        - none
        - incl
      expected_return_codes:
        description:
          - Set expected response status code.
        required: false
        default: null
        type: str
      return_value:
        description:
          - Set expected response string.
        required: false
        default: null
        type: str
      overload_value:
        description:
          - Set expected response string for server overload.
        required: false
        default: null
        type: str
      proxy_request:
        description:
          - Enable/disable proxy request.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      https_cipher:
        description:
          - Set cipher-suite for HTTPS Health check.
        required: false
        default: null
        choices:
        - userDefined
        - low
        - medium
        - high
      https_user_defined_cipher:
        description:
          - Set user-defined cipher-suite for HTTPS Health check.
        required: false
        default: null
        type: str
      http2:
        description:
          - Enable/disable HTTP/2.
        required: false
        default: null
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
  alteon_config_health_check_http:
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
      index: test_http_hc
      description: test_http_hc
      ip_ver: ipv4
      destination_ip_or_hostname: 1.1.1.1
      connection_termination: rst
      standalone_real_hc_mode: enabled
      interval_second: 5
      interval_downtime_second: 4
      https: enabled
      http2: enabled
      http_hostname: hostanme.com
      return_string_lookup_type: incl
      overload_string_lookup_type: incl
      return_value: some_value
      overload_value: overload_value
      https_cipher: userDefined
      https_user_defined_cipher: ALL:!DH:!NULL:!aNULL:!EXPORT:!RC4:!RC2:!3DES:!DES:!DSS:!SRP:!PSK:!IDEA:!SSLv2:!RSA
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
from radware.alteon.sdk.configurators.health_check_http import HealthCheckHTTPConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(HealthCheckHTTPConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(HealthCheckHTTPConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
