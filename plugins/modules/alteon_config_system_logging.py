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
module: alteon_config_system_logging
short_description: Manage system logging in Radware Alteon
description:
  - Manage system logging in Radware Alteon.
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
      - Parameters system logging configuration.
    suboptions:
      show_syslog_on_console:
        description:
          - Specifies whether to enable console output of syslog messages.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      configuration_audit:
        description:
          - Specifies whether to log the details of all configuration changes to the syslog server.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      extended_log_format:
        description:
          - Enables or disables extended information in syslog messages.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      session_log_state:
        description:
          - Enables or disables session log.
          - Caution: Turning on the session log may impair Alteon traffic-processing performance.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      session_log_server_data:
        description:
          - Enables or disables log real server data.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      session_log_nat_data:
        description:
          - Enables or disables log NAT data.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      session_log_mode:
        description:
          - Specifies the session log connection mode.
          - Depending on the configuration, session logs can be sent via the management port to the syslog servers or saved to disk to export later, or to both.
        required: false
        default: null
        choices:
        - syslog
        - disk
        - both
      log_trap_system:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to the system.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_spanning_tree:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to spanning tree.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_vlan:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to VLAN.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_virtual_services:
        description:
          - Specifies whether Alteon sends all syslogs and SNMP traps relating to SLB.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_security:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to the Security packs.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_management:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to management.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_vrrp:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to legacy VRRP.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_filter:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to the filter.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ip_reputation:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to IP reputation.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_cli:
        description:
          - Specifies whether Alteon sends CLI-generated errors.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ip:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to IP.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_global_lb:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to GSLB.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ssh:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to SSH RADIUS.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ipv6:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to IPv6.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_syn_attack:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to SYN-attack detection.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ntp:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to NTP.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ospf:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to OSPF.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_app_services:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to application services.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_web:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to WEB UI.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_ospf_v3:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to OSPFv3.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_slb_attack:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to SLB attacks.
          - This parameter is not displayed in ADC-VX mode.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_audit:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to audit.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_bgp:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to BGP.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_fastview:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to FastView.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_rate_limit:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to TCP-rate-limiting.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_high_availability:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to high availability.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_rmon:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to RMON.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      log_trap_console:
        description:
          - Specifies whether Alteon sends syslogs and SNMP traps relating to the console.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      syslog_servers:
        description:
          - Syslog servers configuration.
        required: false
        default: null
        suboptions:
          host1:
            description:
              - Host 1 configuration.
            required: false
            default: null
            suboptions:
              ip4_address:
                description:
                  - The IPv4 address of the syslog server.
                required: false
                default: null
                type: str
              ip6_address:
                description:
                  - The IPv6 address of the syslog server.
                required: false
                default: null
                type: str
              port:
                description:
                  - The port number of the syslog server.
                required: false
                default: null
                type: int
              severity:
                description:
                  - The lowest severity messages that Alteon sends to the syslog server.
                required: false
                default: null
                choices:
                - emerg0
                - alert1
                - crit2
                - err3
                - warning4
                - notice5
                - info6
                - debug7
              facility:
                description:
                  - The facility of syslog server.
                required: false
                default: local0
                choices:
                - local0
                - local1
                - local2
                - local3
                - local4
                - local5
                - local6
                - local7
              module:
                description:
                  - Specifies whether to send syslog messages generated by a specific module or module group to the specified syslog server (host 1 through host 5).
                  - If a module group is specified, messages generated by all the modules included in the group are enabled for logging and routed to the syslog server.
                required: false
                default: all
                choices:
                - all
                - grpmng
                - grpsys
                - grpnw
                - grpslb
                - grpsec
                - fastview
                - ha
                - appsvc
                - bgp
                - filter
                - gslb
                - ip
                - ipv6
                - ospf
                - ospfv3
                - ratelim
                - rmon
                - security
                - slb
                - slbatk
                - synatk
                - vlan
                - vrrp
                - cli
                - console
                - mgmt
                - ntp
                - ssh
                - stp
                - system
                - web
                - audit
          host2:
            description:
              - Host 2 configuration.
            required: false
            default: null
            suboptions:
              ip4_address:
                description:
                  - The IPv4 address of the syslog server.
                required: false
                default: null
                type: str
              ip6_address:
                description:
                  - The IPv6 address of the syslog server.
                required: false
                default: null
                type: str
              port:
                description:
                  - The port number of the syslog server.
                required: false
                default: null
                type: int
              severity:
                description:
                  - The lowest severity messages that Alteon sends to the syslog server.
                required: false
                default: null
                choices:
                - emerg0
                - alert1
                - crit2
                - err3
                - warning4
                - notice5
                - info6
                - debug7
              facility:
                description:
                  - The facility of syslog server.
                required: false
                default: local0
                choices:
                - local0
                - local1
                - local2
                - local3
                - local4
                - local5
                - local6
                - local7
              module:
                description:
                  - Specifies whether to send syslog messages generated by a specific module or module group to the specified syslog server (host 1 through host 5).
                  - If a module group is specified, messages generated by all the modules included in the group are enabled for logging and routed to the syslog server.
                required: false
                default: all
                choices:
                - all
                - grpmng
                - grpsys
                - grpnw
                - grpslb
                - grpsec
                - fastview
                - ha
                - appsvc
                - bgp
                - filter
                - gslb
                - ip
                - ipv6
                - ospf
                - ospfv3
                - ratelim
                - rmon
                - security
                - slb
                - slbatk
                - synatk
                - vlan
                - vrrp
                - cli
                - console
                - mgmt
                - ntp
                - ssh
                - stp
                - system
                - web
                - audit
          host3:
            description:
              - Host 3 configuration.
            required: false
            default: null
            suboptions:
              ip4_address:
                description:
                  - The IPv4 address of the syslog server.
                required: false
                default: null
                type: str
              ip6_address:
                description:
                  - The IPv6 address of the syslog server.
                required: false
                default: null
                type: str
              port:
                description:
                  - The port number of the syslog server.
                required: false
                default: null
                type: int
              severity:
                description:
                  - The lowest severity messages that Alteon sends to the syslog server.
                required: false
                default: null
                choices:
                - emerg0
                - alert1
                - crit2
                - err3
                - warning4
                - notice5
                - info6
                - debug7
              facility:
                description:
                  - The facility of syslog server.
                required: false
                default: local0
                choices:
                - local0
                - local1
                - local2
                - local3
                - local4
                - local5
                - local6
                - local7
              module:
                description:
                  - Specifies whether to send syslog messages generated by a specific module or module group to the specified syslog server (host 1 through host 5).
                  - If a module group is specified, messages generated by all the modules included in the group are enabled for logging and routed to the syslog server.
                required: false
                default: all
                choices:
                - all
                - grpmng
                - grpsys
                - grpnw
                - grpslb
                - grpsec
                - fastview
                - ha
                - appsvc
                - bgp
                - filter
                - gslb
                - ip
                - ipv6
                - ospf
                - ospfv3
                - ratelim
                - rmon
                - security
                - slb
                - slbatk
                - synatk
                - vlan
                - vrrp
                - cli
                - console
                - mgmt
                - ntp
                - ssh
                - stp
                - system
                - web
                - audit
          host4:
            description:
              - Host 4 configuration.
            required: false
            default: null
            suboptions:
              ip4_address:
                description:
                  - The IPv4 address of the syslog server.
                required: false
                default: null
                type: str
              ip6_address:
                description:
                  - The IPv6 address of the syslog server.
                required: false
                default: null
                type: str
              port:
                description:
                  - The port number of the syslog server.
                required: false
                default: null
                type: int
              severity:
                description:
                  - The lowest severity messages that Alteon sends to the syslog server.
                required: false
                default: null
                choices:
                - emerg0
                - alert1
                - crit2
                - err3
                - warning4
                - notice5
                - info6
                - debug7
              facility:
                description:
                  - The facility of syslog server.
                required: false
                default: local0
                choices:
                - local0
                - local1
                - local2
                - local3
                - local4
                - local5
                - local6
                - local7
              module:
                description:
                  - Specifies whether to send syslog messages generated by a specific module or module group to the specified syslog server (host 1 through host 5).
                  - If a module group is specified, messages generated by all the modules included in the group are enabled for logging and routed to the syslog server.
                required: false
                default: all
                choices:
                - all
                - grpmng
                - grpsys
                - grpnw
                - grpslb
                - grpsec
                - fastview
                - ha
                - appsvc
                - bgp
                - filter
                - gslb
                - ip
                - ipv6
                - ospf
                - ospfv3
                - ratelim
                - rmon
                - security
                - slb
                - slbatk
                - synatk
                - vlan
                - vrrp
                - cli
                - console
                - mgmt
                - ntp
                - ssh
                - stp
                - system
                - web
                - audit
          host5:
            description:
              - Host 5 configuration.
            required: false
            default: null
            suboptions:
              ip4_address:
                description:
                  - The IPv4 address of the syslog server.
                required: false
                default: null
                type: str
              ip6_address:
                description:
                  - The IPv6 address of the syslog server.
                required: false
                default: null
                type: str
              port:
                description:
                  - The port number of the syslog server.
                required: false
                default: null
                type: int
              severity:
                description:
                  - The lowest severity messages that Alteon sends to the syslog server.
                required: false
                default: null
                choices:
                - emerg0
                - alert1
                - crit2
                - err3
                - warning4
                - notice5
                - info6
                - debug7
              facility:
                description:
                  - The facility of syslog server.
                required: false
                default: local0
                choices:
                - local0
                - local1
                - local2
                - local3
                - local4
                - local5
                - local6
                - local7
              module:
                description:
                  - Specifies whether to send syslog messages generated by a specific module or module group to the specified syslog server (host 1 through host 5).
                  - If a module group is specified, messages generated by all the modules included in the group are enabled for logging and routed to the syslog server.
                required: false
                default: all
                choices:
                - all
                - grpmng
                - grpsys
                - grpnw
                - grpslb
                - grpsec
                - fastview
                - ha
                - appsvc
                - bgp
                - filter
                - gslb
                - ip
                - ipv6
                - ospf
                - ospfv3
                - ratelim
                - rmon
                - security
                - slb
                - slbatk
                - synatk
                - vlan
                - vrrp
                - cli
                - console
                - mgmt
                - ntp
                - ssh
                - stp
                - system
                - web
                - audit
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_system_logging:
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
      show_syslog_on_console: enabled
      configuration_audit: enabled
      extended_log_format: enabled
      session_log_state: enabled
      session_log_mode: disk
      log_trap_system: enabled
      log_trap_management: enabled
      log_trap_virtual_services: enabled
      log_trap_cli: disabled
      log_trap_bgp: enabled
      syslog_servers:
      host1:
        ip4_address: 10.10.10.1
        port: 514
        severity: warning4
        facility: local5
        module: all
      host3:
        ip4_address: 10.10.10.2
        port: 514
        severity: notice5
        facility: local3
        module: appsvc
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
from radware.alteon.sdk.configurators.system_logging import SystemLoggingConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SystemLoggingConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SystemLoggingConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

