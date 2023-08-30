#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Radware LTD.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: alteon_config_sideband_policy
short_description: create and manage sideband policy in Radware Alteon
description:
  - create and manage sideband policy in Radware Alteon.
version_added: '2.9'
author:
  - Michal Greenberg (@michalgreenberg)
options:
  provider:
    description:
      - Radware Alteon connection details.
    required: true
    suboptions:
      server:
        description:
          - Radware Alteon IP address.
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
      - When C(overwrite), removes the object if exists then recreate it.
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
      - Parameters for sideband policy configuration.
    suboptions:
      sideband_policy_id:
        description:
          - sideband policy index.
        required: true
        default: null
        type: str
      name:
        description:
          - Set Descriptive name for the sideband policy.
        required: false
        default: null
        type: str
      destination_port:
        description:
          - Set sideband destination application port.
        required: false
        default: null
        type: int
      group_id:
        description:
          - Set sideband destination group.
        required: false
        default: null
        type: str
      ssl_policy:
        description:
          - Set sideband backend SSL policy. This field can be set only when sideband policy is http application mode.
        required: false
        default: null
        type: str
      sideband_policy_state:
        description:
          - Enable/Disable the sideband policy.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      timeout:
        description:
          - Set sideband timeout.
        required: false
        default: null
        type: int
      application:
        description:
          - Set sideband policy application.
        required: false
        default: http
        choices:
        - http
        - dns
      client_nat_mode:
        description:
          - Set client NAT mode.
        required: false
        default: egress
        choices:
        - egress
        - address
      client_nat_addr:
        description:
          - Set cilent IPv4 address.
        required: false
        default: null
        type: str
      client_nat_mask:
        description:
          - Set client NAT mask.
        required: false
        default: null
        type: str
      client_nat_v6_addr:
        description:
          - Set cilent IPv6 address.
        required: false
        default: null
        type: str
      client_nat_prefix:
        description:
          - Set client NAT prefix.
        required: false
        default: null
        type: int
      fallback_action:
        description:
          - Set the fallback action in case of no-response or failure.
          - This field can be set only when sideband policy is http application mode.
        required: false
        default: fallbackOpen
        choices:
        - fallbackClosed
        - fallbackOpen
      preserve_client_ip:
        description:
          - Enable/Disable preserving client IP. This field can be set only when sideband policy is dns application mode.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      appshapes:
        description:
          - Associate Appshape scripts to sideband policy.
        required: false
        default: null
        elements: dict
        suboptions:
          priority:
            description:
              - Appshape script priority.
            required: true
            type: int
          name:
            description:
              - Appshape script name.
            required: false
            type: str
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_sideband_policy:
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
      sideband_policy_id: 3
      name: sideband3
      sideband_policy_state: enabled
      group_id: group1
    appshapes:
      - priority: 3
        name: SecurePath_sideband_script
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
import logging

from ansible_collections.radware.radware_modules.plugins.module_utils.common import RadwareModuleError
from ansible_collections.radware.radware_modules.plugins.module_utils.alteon import AlteonConfigurationModule, \
    AlteonConfigurationArgumentSpec as ArgumentSpec
from radware.alteon.sdk.configurators.sideband_policy import SidebandPolicyConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SidebandPolicyConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SidebandPolicyConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    # logging.basicConfig(filename="logSideband.txt", filemode='a',
    #      format='[%(levelname)s %(asctime)s %(filename)s:%(lineno)s %(funcName)s]\n%(message)s',
    #      level=logging.DEBUG, datefmt='%d-%b-%Y %H:%M:%S')
    # log = logging.getLogger()

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
