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
module: alteon_config_slb_pip6
short_description: Manage SLB PIP version IPv6 in Radware Alteon
description:
    - Manage SLB PIP in Radware Alteon 
version_added: null
author: 
  - Nofar Livkind 
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
        - If an error occurs, perform revert on alteon
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
            - Parameters for SLB PIP configuration.
        suboptions:
            pip6_addr:
                  description:
                    - The IPv6 address of the SLB PIP6.
                  required: true
                  default: null
                  type: str
            base_type:
                description:
                    - The SLB PIP base type
                    - Can be "port" or "vlan".
                required: true
                default: port
                type: str
            ports:
                description:
                    - Alteon ports for SLB PIP6.
                    - This parameter must be equivalent to 'base_type' parameter 'port'.
                required: false
                default: null
                type: list
                elements: int
            vlans:
                description:
                    - Alteon VLANs for SLB PIP6.
                    - This parameter must be equivalent to 'base_type' parameter 'vlan'.
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
      alteon_config_slb_pip6:
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
          pip6_addr: 44::44
          base_type: port
          ports:
            - 1
            - 2
          vlans: null
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
from radware.alteon.sdk.configurators.slb_pip6 import SlbPip6Configurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SlbPip6Configurator, **kwargs)


def main():
    spec = ArgumentSpec(SlbPip6Configurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
