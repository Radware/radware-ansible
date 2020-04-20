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
module: alteon_config_vadc_instance
short_description: Manage vADC instance in Radware Alteon
description:
  - Manage vADC instance in Radware Alteon.
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
      - Parameters for vADC instance configuration.
    suboptions:
      index:
        description:
          - The vADC ID.
        required: true
        default: null
        type: int
      vadc_system_name:
        description:
          - The vADC name.
        required: false
        default: null
        type: str
      state:
        description:
          - Enable/Disable the vADC capacity unit.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      capacity_units:
        description:
          - The number of CUs allocated for traffic processing.
        required: false
        default: null
        type: int
      throughput_limit_mbps:
        description:
          - The maximum available throughput, in Mbit/s, for vADC allocation, which is determined by the device throughput license.
        required: false
        default: null
        type: int
      appwall_capacity_units:
        description:
          - The number of CUs allocated for the AppWall component on the vADC.
        required: false
        default: null
        type: int
      fastview_capacity_units:
        description:
          - The maximum pages per second (PgPS) that the FastView component on the vADC can process.
        required: false
        default: 0
        type: int
      ssl_cps_limit:
        description:
          - The maximum SSL CPS for vADC allocation.
        required: false
        default: 0
        type: int
      compression_limit_mbps:
        description:
          - The maximum compression, in Mbit/s, for vADC allocation.
        required: false
        default: 0
        type: int
      apm_pages_per_minute_limit:
        description:
          -The maximum APM pages per minute that the vADC sends to APM.
        required: false
        default: 0
        type: int
      waf_limit_mbps:
        description:
          - The maximum Mbit/s that the AppWall component on the vADC can process.
        required: false
        default: null
        type: int
      authentication_user_limit:
        description:
          - The maximum users that the AppWall component on the vADC can process.
        required: false
        default: null
        type: int
      feature_global:
        description:
          - Specifies whether to enable Global Server Load Balancing.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      feature_bwm:
        description:
          - Specifies whether to enable Bandwidth Management.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      feature_ados:
        description:
          - Specifies whether to enable Advanced Denial of Service.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      fastview_pages_per_minute_limit:
        description:
          - The maximum pages per second (PgPS) that the FastView component on the vADC can process.
        required: false
        default: 0
        type: int
      feature_linkproof:
        description:
          - Specifies whether to enable Inbound Link Load Balancing.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      feature_ip_reputation:
        description:
          - Specifies whether to enable or disable the IP reputation feature for this vADC.
          - IP reputation is a security feature that protects Alteon from known malicious IP addresses.
          - Using a dynamic list of IP addresses list, the Alteon security administrator can easily and effectively stop network-based IP threats that are targeting the network.
          - The administrator can define whether to allow, block, or alert malicious IP addresses based on region, category (SPAM or MALWARE), or risk severity level.
          - An IP reputation license is required for IP reputation functionality.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      feature_url_filtering:
        description:
          - Specifies whether to enable the URL Filtering license for the vADC.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      vadc_ha_id:
        description:
          - The peer switch assigned to the vADC.
        required: false
        default: null
        type: int
      management_ip4_address:
        description:
          - The IPv4 address.
        required: false
        default: null
        type: str
      management_ip4_mask:
        description:
          - The IPv4 mask.
        required: false
        default: null
        type: str
      management_ip4_gateway:
        description:
          - The IPv4 default gateway.
        required: false
        default: null
        type: str
      management_ip6_address:
        description:
          - The IPv6 address.
        required: false
        default: null
        type: str
      management_ip6_prefix:
        description:
          - The IPv6 prefix.
        required: false
        default: null
        type: int
      management_ip6_gateway:
        description:
          - The IPv6 default gateway.
        required: false
        default: null
        type: str
      vadc_https_access:
        description:
          - Specifies whether HTTPS is enabled.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      vadc_ssh_access:
        description:
          - Specifies whether SSH is enabled.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      vadc_snmp_access:
        description:
          - Specifies whether SNMP is enabled.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      delegation_vx_management:
        description:
          - Specifies whether Delegate Settings are enabled.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      delegation_vx_syslog:
        description:
          - Specifies whether syslog is enabled in the vADC.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      delegation_vx_radius:
        description:
          - Specifies whether RADIUS is enabled in the vADC.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      delegation_vx_tacacs:
        description:
          - Specifies whether TACACS is enabled in the vADC.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      delegation_vx_smtp:
        description:
          - Specifies whether SMTP is enabled in the vADC.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      lock_vadc_management:
        description:
          - Specifies whether Delegate Services Locking is locked.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      lock_vadc_syslog:
        description:
          - Specifies whether the syslog servers are locked.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      lock_vadc_radius:
        description:
          - Specifies whether the RADIUS servers are locked.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      lock_vadc_tacacs:
        description:
          - Specifies whether the TACACS servers are locked.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      lock_vadc_smtp:
        description:
          - Specifies whether the SMTP servers are locked.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      vx_admin_password:
        description:
          - VX admin user password.
        required: false
        default: null
        type: str
      vadc_admin_password:
        description:
          - vADC admin user password.
        required: false
        default: null
        type: str
      vlans:
        description:
          - VLANs to add to the vADC.
        required: false
        default: null
        type: list
        elements: int
      vadc_peer_id:
        description:
          - The peer ID.
        required: false
        default: null
        type: int
      vadc_peer_name:
        description:
          - The peer name.
        required: false
        default: null
        type: str
      vadc_peer_ip4:
        description:
          - The IPv4 address.
        required: false
        default: null
        type: str
      vadc_peer_ip4_gateway:
        description:
          - The IPv4 default gateway.
        required: false
        default: null
        type: str
      vadc_peer_subnet:
        description:
          - The IPv4 mask.
        required: false
        default: null
        type: str
      vadc_peer_ip6:
        description:
          - The IPv6 address.
        required: false
        default: null
        type: str
      vadc_peer_prefix:
        description:
          - The IPv6 prefix.
        required: false
        default: null
        type: int
      vadc_peer_ip6_gateway:
        description:
          - The IPv6 default gateway.
        required: false
        default: null
        type: str
      management_nets:
        description:
          - Allowed Networks for vADCs.
        required: false
        default: null
        type: list
        elements:
          vlan:
            description:
              - The VLAN ID of the allowed network.
            required: true
            default: null
            type: int
          ip_ver:
            description:
              - Specifies the type of IP address.
            required: false
            default: ipv4
            choices:
            - ipv4
            - ipv6
          ip4_net_address:
            description:
              - The IP network address.
            required: false
            default: null
            type: str
          ip4_subnet:
            description:
              - The IP network mask.
            required: false
            default: null
            type: str
          ip6_net_address:
            description:
              - The IP network address.
            required: false
            default: null
            type: str
          ip6_prefix:
            description:
              - The IP network prefix.
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
  alteon_config_vadc_instance:
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
      capacity_units: 4
      throughput_limit_mbps: 200
      feature_global: enabled
      management_ip4_address: 172.16.1.1
      management_ip4_mask: 255.255.255.0
      management_ip4_gateway: 172.16.1.254
      vadc_https_access: enabled
      vadc_ssh_access: enabled
      lock_vadc_management: enabled
      delegation_vx_management: enabled
      delegation_vx_syslog: enabled
      vx_admin_password: radware
      vadc_admin_password: radware
      vadc_peer_id: 6
      vadc_peer_name: peer_vadc_6
      vadc_peer_ip4: 172.16.1.1
      vadc_peer_ip4_gateway: 172.16.1.254
      vlans:
        - 45
        - 47
      management_nets:
        - vlan: 10
          ip4_net_address: 172.16.5.0
          ip4_subnet: 255.255.255.0
        - vlan: 20
          ip4_net_address: 172.16.3.0
          ip4_subnet: 255.255.255.0
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
from radware.alteon.sdk.configurators.vadc_instance import VADCInstanceConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(VADCInstanceConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(VADCInstanceConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

