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
module: alteon_config_system_management_access
short_description: Manage management access in Radware Alteon
description:
  - Manage management access in Radware Alteon.
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
      - Parameters management access configuration.
    suboptions:
      management_port_state:
        description:
          - Specifies whether to enable the management port.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      management_ip4_address:
        description:
          - The management IPv4 address.
        required: false
        default: null
        type: str
      management_ip6_address:
        description:
          - The management IPv6 address.
        required: false
        default: null
        type: str
      management_ip4_subnet:
        description:
          - The IPv4 subnet mask
        required: false
        default: null
        type: str
      management_ip6_prefix:
        description:
          - The IPv6 prefix.
        required: false
        default: null
        type: int
      management_ip4_gateway:
        description:
          - The default gateway IP address.
        required: false
        default: null
        type: str
      management_ip6_gateway:
        description:
          - The default gateway IP address.
        required: false
        default: null
        type: str
      single_ip_cloud_mode:
        description:
          - Enable/disable Single IP operation mode.
        required: false
        default: null
        choices:
        - unsupported
        - enabled
        - disabled
      gateway_health_check:
        description:
          - The type of gateway health check.
        required: false
        default: null
        choices:
        - arp
        - icmp
      gateway_health_check_interval:
        description:
          - The time, in seconds, between gateway health checks.
        required: false
        default: null
        type: int
      gateway_health_check_retries:
        description:
          - The number of gateway-health-checks attempts before considering the gateway down.
        required: false
        default: null
        type: int
      management_port_autonegotiation:
        description:
          - Specifies whether to enable auto-negotiation.
        required: false
        default: on
        choices:
        - on
        - off
      management_port_speed:
        description:
          - Management port speed.
        required: false
        default: any
        choices:
        - mbs10
        - mbs100
        - mbs1000
        - any
      management_port_duplex:
        description:
          - Management port duplex.
        required: false
        default: any
        choices:
        - full
        - half
        - any
      idle_timeout_minute:
        description:
          - The idle timeout, in minutes, for CLI sessions.
        required: false
        default: 20
        type: int
      language_display:
        description:
          - Sets the global default language for the Alteon Web Based Management (WBM) interface.
          - Sets the Alteon Web Based Management (WBM) interface language for a local user.
        required: false
        default: english
        choices:
        - english
        - chinese
        - korean
        - japanese
      ssh_state:
        description:
          - Specifies whether to enable Alteon-device management over SSH.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      ssh_port:
        description:
          - The number of the SSH server port.
        required: false
        default: 22
        type: int
      ssh_version1:
        description:
          - Specifies whether to enable SSH Version 1.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      ssh_scp_apply_save:
        description:
          - Specifies whether to enable SCP Apply and Save.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      telnet_state:
        description:
          - Specifies whether to enable Alteon-device management over Telnet.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      telnet_port:
        description:
          - The TCP port number that the Telnet management listens for Telnet sessions.
        required: false
        default: 23
        type: int
      https_state:
        description:
          - Specifies whether to enable Alteon-device management over HTTPS.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      https_port:
        description:
          - The TCP port number that the HTTPS server listens to.
        required: false
        default: null
        type: int
      https_cert_name:
        description:
          - HTTPS certificate name
        required: false
        default: null
        type: str
      https_intermediate_chain_type:
        description:
          - Select the Intermediate CA type.
        required: false
        default: none
        choices:
        - group
        - cert
        - none
      https_intermediate_chain_name:
        description:
          - Intermediate CA certificate name.
        required: false
        default: null
        type: str
      https_ssl_tls1_0:
        description:
          - Allowe TLS 1.0 for the management connection.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      https_ssl_tls1_1:
        description:
          - Allowe TLS 1.1 for the management connection.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      https_ssl_tls1_2:
        description:
          - Allowe TLS 1.2 for the management connection.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      cli_login_banner:
        description:
          - The user-defined login banner.
        required: false
        default: null
        type: str
      cli_login_notice:
        description:
          - The user-defined login notice.
        required: false
        default: null
        type: str
      cli_hostname_prompt:
        description:
          - Enable or disable CLI hostname prompt.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      radius_traffic_port:
        description:
          - Specifies whether RADIUS server access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      tacacs_traffic_port:
        description:
          - Specifies whether TACACS+ server access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      syslog_traffic_port:
        description:
          - Specifies whether syslog host access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      snmp_traffic_port:
        description:
          - Specifies whether SNMP trap host access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      tftp_traffic_port:
        description:
          - Specifies whether TFTP access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      dns_traffic_port:
        description:
          - Specifies whether DNS access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      ocsp_traffic_port:
        description:
          - Specifies whether OCSP access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      cdp_traffic_port:
        description:
          - Specifies whether CDP access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      wlm_sasp_traffic_port:
        description:
          - Specifies whether WLM SASP is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      smtp_traffic_port:
        description:
          - Specifies whether SMTP access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      webapp_radius_traffic_port:
        description:
          - Specifies whether access of RADIUS servers for Web security is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      webapp_ldap_traffic_port:
        description:
          - Specifies whether access of LDAP servers for Web security is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      dp_signaling_traffic_port:
        description:
          - Specifies whether access of DefensePro signaling servers for Web security is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      ntp_traffic_port:
        description:
          - Specifies whether NTP access is over a data port or the management port.
        required: false
        default: data
        choices:
        - data
        - mgmt
      management4_nets:
        description:
          - Allowed protocols per IPv4 network.
        required: false
        default: null
        type: list
        elements:
          ip_address:
            description:
              - The IPv4 management network address.
            required: false
            default: null
            type: str
          ip_subnet:
            description:
              - The management network mask.
            required: false
            default: null
            type: str
          protocols:
            description:
              - Allowed Protocols per IPv4 Network Parameters.
            required: false
            default: null
            choices:
            - ssh
            - telnet
            - sshTelnet
            - http
            - sshHttp
            - telnetHttp
            - sshTelnetHttp
            - https
            - sshHttps
            - httpsTelnet
            - sshTelnetHttps
            - httpHttps
            - sshHttpHttps
            - telnetHttpHttps
            - sshTelnetHttpHttps
            - snmp
            - sshSnmp
            - telnetSnmp
            - sshTelnetSnmp
            - httpSnmp
            - sshHttpSnmp
            - telnetHttpSnmp
            - sshTelnetHttpSnmp
            - httpsSnmp
            - sshHttpsSnmp
            - telnetHttpsSnmp
            - sshTelnetHttpsSnmp
            - httpHttpsSnmp
            - sshHttpHttpsSnmp
            - telnetHttpHttpsSnmp
            - sshTelnetHttpHttpsSnmp
            - report
            - sshreport
            - telnetreport
            - sshTelnetreport
            - httpreport
            - sshHttpreport
            - telnetHttpreport
            - sshTelnetHttpreport
            - httpsreport
            - sshHttpsreport
            - httpsTelnetreport
            - sshTelnetHttpsreport
            - httpHttpsreport
            - sshHttpHttpsreport
            - telnetHttpHttpsreport
            - sshTelnetHttpHttpsreport
            - snmpreport
            - sshSnmpreport
            - telnetSnmpreport
            - sshTelnetSnmpreport
            - httpSnmpreport
            - sshHttpSnmpreport
            - telnetHttpSnmpreport
            - sshTelnetHttpSnmpreport
            - httpsSnmpreport
            - sshHttpsSnmpreport
            - telnetHttpsSnmpreport
            - sshTelnetHttpsSnmpreport
            - httpHttpsSnmpreport
            - sshHttpHttpsSnmpreport
            - telnetHttpHttpsSnmpreport
            - sshTelnetHttpHttpsSnmpreport
            - none
      management6_nets:
        description:
          - Allowed protocols per IPv6 network.
        required: false
        default: null
        type: list
        elements:
          ip_address:
            description:
              - The IPv6 management network address.
            required: false
            default: null
            type: str
          ip_prefix:
            description:
              - The IPv6 management network prefix.
            required: false
            default: null
            type: str
          protocols:
            description:
              - Allowed Protocols per IPv6 Network Parameters.
            required: false
            default: null
            choices:
            - ssh
            - telnet
            - sshTelnet
            - http
            - sshHttp
            - telnetHttp
            - sshTelnetHttp
            - https
            - sshHttps
            - httpsTelnet
            - sshTelnetHttps
            - httpHttps
            - sshHttpHttps
            - telnetHttpHttps
            - sshTelnetHttpHttps
            - snmp
            - sshSnmp
            - telnetSnmp
            - sshTelnetSnmp
            - httpSnmp
            - sshHttpSnmp
            - telnetHttpSnmp
            - sshTelnetHttpSnmp
            - httpsSnmp
            - sshHttpsSnmp
            - telnetHttpsSnmp
            - sshTelnetHttpsSnmp
            - httpHttpsSnmp
            - sshHttpHttpsSnmp
            - telnetHttpHttpsSnmp
            - sshTelnetHttpHttpsSnmp
            - report
            - sshreport
            - telnetreport
            - sshTelnetreport
            - httpreport
            - sshHttpreport
            - telnetHttpreport
            - sshTelnetHttpreport
            - httpsreport
            - sshHttpsreport
            - httpsTelnetreport
            - sshTelnetHttpsreport
            - httpHttpsreport
            - sshHttpHttpsreport
            - telnetHttpHttpsreport
            - sshTelnetHttpHttpsreport
            - snmpreport
            - sshSnmpreport
            - telnetSnmpreport
            - sshTelnetSnmpreport
            - httpSnmpreport
            - sshHttpSnmpreport
            - telnetHttpSnmpreport
            - sshTelnetHttpSnmpreport
            - httpsSnmpreport
            - sshHttpsSnmpreport
            - telnetHttpsSnmpreport
            - sshTelnetHttpsSnmpreport
            - httpHttpsSnmpreport
            - sshHttpHttpsSnmpreport
            - telnetHttpHttpsSnmpreport
            - sshTelnetHttpHttpsSnmpreport
            - none
      data_ports_allow_mng:
        description:
          - Data port access for management traffic.
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
  alteon_config_system_management_access:
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
      telnet_state: enabled
      cli_hostname_prompt: enabled
      idle_timeout_minute: 800
      gateway_health_check: arp
      https_ssl_tls1_0: disabled
      dns_traffic_port: data
      dp_signaling_traffic_port: data
      data_ports_allow_mng:
        - 1
        - 2
      management4_nets:
        - ip_address: 192.0.0.0
          ip_subnet: 255.0.0.0
          protocols: sshTelnetHttpsSnmp
        - ip_address: 172.16.0.0
          ip_subnet: 255.255.0.0
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
from radware.alteon.sdk.configurators.system_management_access import ManagementAccessConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(ManagementAccessConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(ManagementAccessConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

