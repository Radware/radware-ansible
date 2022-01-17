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
module: alteon_config_gel
short_description: Manage GEL parameters in Radware Alteon
description:
  - configure GEL parameters in Radware Alteon. 
version_added: '2.9'
author: 
  - Ofer Epstein (@ofere)
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
      - GEL parameters configuration.
    suboptions:
      state:
        description:
          - Enable/Disable license server integration.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      primary_url:
        description:
          - Set primary license server IP address or URL.
        required: false
        default: null
        type: str
      secondary_url:
        description:
          - Set secondary license server IP address or URL.
        required: false
        default: null
        type: str
      primary_dns_ipv4:
        description:
          - Set primary IPV4 DNS server address
        required: false
        default: null
        type: str
      secondary_dns_ipv4:
        description:
          - Set secondary IPV4 DNS server address
        required: false
        default: null
        type: str
      primary_dns_ipv6:
        description:
          - Set primary IPV6 DNS server address
        required: false
        default: null
        type: str
      secondary_dns_ipv6:
        description:
          - Set secondary IPV6 DNS server address
        required: false
        default: null
        type: str
      interval:
        description:
          - Set license revalidation time interval.
        required: false
        default: null
        type: int
      retries:
        description:
          - Set number of retries for determining communication failure.
        required: false
        default: null
        type: int
      retry_interval:
        description:
          - Set the retry interval.
        required: false
        default: null
        type: int
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_gel:
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
      state: enabled
      primary_url: https://a.com
      secondary_url: https://b.com
      primary_dns_ipv4: 1.1.1.1
      secondary_dns_ipv4: 2.2.2.2
      interval: 300
      retries: 3
      retry_interval: 60
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
from radware.alteon.sdk.configurators.gel import GelConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(GelConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(GelConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
