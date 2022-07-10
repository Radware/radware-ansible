#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, Radware LTD. 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: alteon_config_bgp_global
short_description: Manage BGP global parameters in Radware Alteon
description:
  - configure BGP global parameters in Radware Alteon. 
version_added: '2.9'
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
      - When C(absent), when applicable removes the object. Not supported in this module.
      - When C(read), when exists read object from configuration to parameter format.
      - When C(overwrite), removes the object if exists then recreate it. Not supported in this module.
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
      - BGP global parameters configuration.
    suboptions:
      router_id:
        description:
          - Set router ID.
        required: false
        default: null
        type: str
      bgp_status:
        description:
          - enable or disable BGP.
        required: false
        default: off
        choices:
        - on
        - off
      local_preference:
        description:
          - Set Local Preference.
        required: false
        default: null
        type: int
      max_as_path_length:
        description:
          - Set max Autonomous System (AS) path length.
        required: false
        default: null
        type: int
      as_number:
        description:
          - Set Autonomous System (AS) number using plain notation.
          - Use either this or asdot_number (as asdot notation), but not both.
        required: false
        default: null
        type: int
      asdot_status:
        description:
          - Enable/Disable ASDOT Notation.
        required: false
        default: off
        choices:
        - on
        - off
      asdot_number:
        description:
          - Set Autonomous System (AS) number using asdot notation.
          - Use either this or as_number (as plain notation), but not both.
          - thia field is available from alteon versions: 33.0.5.0 and 33.5.1.0
        required: false
        default: null
        type: str
      vip_advertisement:
        description:
          - Enable or Disable sending VIP advertisement.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      floating_ip_advertisement:
        description:
          - Enable or Disable advertising floating IP address.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      bgp_mode:
        description:
          - Set BGP mode (FRR or Legacy).
          - This fields should be set in seperate from the other fields in this module.
          - This fields is supported only on branch 33.0 and up.
        required: false
        default: legacy
        choices:
        - legacy
        - frr
      ecmp_mode:
        description:
          - Set ECMP mode. this field can be set only when BGP mode is in FRR mode.
          - This fields is supported only on branch 33.0 and up.
        required: false
        default: legacy
        choices:
        - off
        - ibgp
        - ebgp
        - eibgp
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_bgp_global:
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
      router_id: 2.2.2.2
      bgp_status: on
      local_preference: 200
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

from ansible_collections.radware.radware_modules.plugins.module_utils.common import RadwareModuleError
from ansible_collections.radware.radware_modules.plugins.module_utils.alteon import AlteonConfigurationModule, \
    AlteonConfigurationArgumentSpec as ArgumentSpec
from radware.alteon.sdk.configurators.bgp_global import BgpGlobalConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(BgpGlobalConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(BgpGlobalConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
