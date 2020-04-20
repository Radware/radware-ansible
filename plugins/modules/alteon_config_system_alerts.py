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
module: alteon_config_system_alerts
short_description: Manage system alerts in Radware Alteon
description:
  - Manage system alerts in Radware Alteon.
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
      - Parameters for system alerts configuration.
    suboptions:
      threshold_detection_interval_minute:
        description:
          - The threshold detection interval, in minutes.
        required: false
        default: null
        type: int
      throughput_threshold_percent:
        description:
          - The threshold, in percent, of the throughput license utilization for sending alerts.
        required: false
        default: null
        type: int
      ssl_cps_threshold_percent:
        description:
          - The threshold, in percent, of the SSL CPS utilization for sending alerts.
        required: false
        default: null
        type: int
      compression_throughput_threshold_percent:
        description:
          - The threshold, in percent, of the compression throughput for sending alerts.
        required: false
        default: null
        type: int
      apm_pgpm_threshold_percent:
        description:
          - The threshold, in percent, of the license capacity APM PgPM (page per minute) for sending an alert.
        required: false
        default: 90
        type: int
      session_table_critical_threshold_percent:
        description:
          - The threshold, in percent, of the session table utilization for sending a critical alert.
        required: false
        default: 90
        type: int
      session_table_high_threshold_percent:
        description:
          - The threshold, in percent, of the session table utilization for sending a high alert.
        required: false
        default: 70
        type: int
      sp_high_utilization_threshold_percent:
        description:
          - The threshold, in percent, of the SP CPU utilization for sending an alert.
        required: false
        default: 80
        type: int
      mp_high_utilization_threshold_percent:
        description:
          - The threshold, in percent, of the MP CPU utilization for sending an alert.
        required: false
        default: 80
        type: int
      disk_critical_utilization_state:
        description:
          - Enable/Disable critical disk utilization alerts.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      disk_extremely_high_utilization_state:
        description:
          - Enable/Disable extremely high disk utilization alerts.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      disk_high_utilization_state:
        description:
          - Enable/Disable high disk utilization alerts.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      disk_critical_utilization_threshold_percent:
        description:
          - The threshold, in a percent, of the disk utilization for sending a critical alert.
        required: false
        default: 95
        type: int
      disk_extremely_high_utilization_threshold_percent:
        description:
          - The threshold, in percent, of the disk utilization for sending an extremely high alert.
        required: false
        default: 90
        type: int
      disk_high_utilization_threshold_percent:
        description:
          - The threshold, in percent, of the disk utilization for sending an high alert.
        required: false
        default: 80
        type: int
      disk_critical_trap_interval_minute:
        description:
          - The interval, in minutes, to resend the critical disk utilization trap.
        required: false
        default: 5
        type: int
      disk_extremely_high_trap_interval_minute:
        description:
          - The interval, in minutes, to resend the extremely high disk utilization trap.
        required: false
        default: 60
        type: int
      disk_high_trap_interval_minute:
        description:
          - The interval, in minutes, to resend the high disk utilization trap.
        required: false
        default: 1440
        type: int
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_system_alerts:
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
      threshold_detection_interval_minute: 4
      throughput_threshold_percent: 92
      ssl_cps_threshold_percent: 92
      session_table_critical_threshold_percent: 92
      sp_high_utilization_threshold_percent: 82
      mp_high_utilization_threshold_percent: 82
      disk_critical_utilization_state: enabled
      disk_critical_utilization_threshold_percent: 92
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
from radware.alteon.sdk.configurators.system_alerts import SystemAlertsConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SystemAlertsConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SystemAlertsConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

