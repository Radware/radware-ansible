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
module: alteon_config_global_redirection
short_description: Manage global traffic redirection in Radware Alteon
description:
  - Manage global traffic redirection (GSLB) in Radware Alteon 
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
      - Parameters for global redirection configuration.
    suboptions:
      state:
        description:
          - Globally turn Global SLB ON/OFF.
        required: false
        default: null
        choices:
        - on
        - off
      global_http_redirection:
        description:
          - Enable/disable HTTP/HTTPS redirection based GSLB.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      global_proxy_redirection:
        description:
          - Enable/disable no remote real SLB.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      redirect_to_server_name:
        description:
          - Enable/disable HTTP redirect to remote real server name.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      session_utilization_threshold_percent:
        description:
          - Set sessions utilization capacity threshold (DSSPv2, DSSPv3, DSSPv4 and DSSPv5).
        required: false
        default: null
        type: int
      cpu_utilization_threshold_percent:
        description:
          - Set CPU utilization capacity threshold (DSSPv2, DSSPv3, DSSPv4 and DSSPv5).
        required: false
        default: null
        type: int
      dssp_version:
        description:
          - Set DSSP version 1 or 2 or 3 or 4 or 5 to send out remote site updates.
        required: false
        default: null
        type: int
      dssp_tcp_update_port:
        description:
          - Set TCP port number for DSSPv2, DSSPv3, DSSPv4 and DSSPv5 remote site updates.
        required: false
        default: null
        type: int
      site_update_interval_second:
        description:
          - Set interval in seconds for remote site updates.
        required: false
        default: null
        type: int
      site_update_encryption:
        description:
          - Enable/disable encrypting remote site updates.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      service_down_response:
        description:
          - Set response when service down.
        required: false
        default: null
        choices:
        - norsp
        - srvfail
      dns_redirection_state:
        description:
          - Enable/disable authoritative DNS direct based GSLB.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      dns_persistence_cache_sync:
        description:
          - Enable/disable sync of DNS persistence cache with remote sites.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      hostname_matching:
        description:
          - Enable/disable virtual service hostname matching.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      dns_persist_ip4_subnet:
        description:
          - Set source IP subnet mask for DNS persistence cache.
        required: false
        default: null
        type: str
      dns_persist_ip6_prefix:
        description:
          - Set source IPv6 prefix for DNS persistence cache.
        required: false
        default: null
        type: int
      dns_persist_timeout_minute:
        description:
          - Set timeout in minutes for DNS persistence cache.
        required: false
        default: null
        type: int
      sites:
        description:
          - Remote site configuration.
        required: false
        default: null
        elements:
          state:
            description:
              - Enable/disable remote site state.
            required: false
            default: null
            choices:
            - enabled
            - disabled
          ha_peer_device:
            description:
              - Enable/disable treatment of site as vrrp peer device.
            required: false
            default: null
            choices:
            - enabled
            - disabled
          description:
            description:
              - Set descriptive remote site name.
            required: false
            default: null
            type: str
          site_update_state:
            description:
              - Enable/disable remote site updates.
            required: false
            default: null
            choices:
            - enabled
            - disabled
          primary_ip4_address:
            description:
              - Set primary switch IPv4 address of remote site.
            required: false
            default: null
            type: str
          primary_ip6_address:
            description:
              - Set primary switch IPv6 address of remote site.
            required: false
            default: null
            type: str
          secondary_ip4_address:
            description:
              - Set secondary switch IPv4 address of remote site.
            required: false
            default: null
            type: str
          secondary_ip6_address:
            description:
              - Set secondary switch IPv6 address of remote site.
            required: false
            default: null
            type: str
          primary_ip_ver:
            description:
              - Set primary switch IP address of remote site.
            required: false
            default: null
            choices:
            - ipv4
            - ipv6
          secondary_ip_ver:
            description:
              - Set secondary switch IP address version of remote site.
            required: false
            default: null
            choices:
            - ipv4
            - ipv6
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_global_redirection:
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
      global_http_redirection: disabled
      global_proxy_redirection: enabled
      cpu_utilization_threshold_percent: 90
      dssp_version: 5
      dssp_tcp_update_port: 8080
      site_update_interval_second: 45
      site_update_encryption: enabled
      service_down_response: norsp
      dns_redirection_state: enabled
      dns_persistence_cache_sync: enabled
      hostname_matching: enabled
      dns_persist_timeout_minute: 30
      dns_persist_ip4_subnet: 255.255.255.128
      sites:
        - state: enabled
          description: site_x
          site_update_state: enabled
          primary_ip4_address: 8.5.5.5
          secondary_ip4_address: 8.5.5.6
        - state: enabled
          description: ha_peer_device
          site_update_state: enabled
          ha_peer_device: enabled
          primary_ip4_address: 1.1.1.2                
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
from radware.alteon.sdk.configurators.global_traffic_redirection import GlobalRedirectionConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(GlobalRedirectionConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(GlobalRedirectionConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

