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
module: alteon_config_secure_path_policy
short_description: create and manage secure path policy in Radware Alteon
description:
  - create and manage secure path policy in Radware Alteon.
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
      - Parameters for secure path policy configuration.
    suboptions:
      secure_path_id:
        description:
          - secure path policy index.
        required: true
        default: null
        type: str
      name:
        description:
          - Set Descriptive name for secure path policy.
        required: false
        default: null
        type: str
      secure_path_policy_status:
        description:
          - Enable/Disable the secure path policy.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      bot_manager_status:
        description:
          - Enable/Disable the Bot manager integration.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      api_key:
        description:
          - Copy here the API Key of the application from Radware portal (in UUID format).
        required: false
        default: null
        type: str
      application_id:
        description:
          - Copy the Application ID of the application from Radware Portal (available at the URL) in UUID format.
        required: false
        default: null
        type: str
      file_extensions_to_bypass:
        description:
          - List the static file extensions to bypass with pipe separation (case-sensitive). Spaces are not allowed.
          - Default Value:png|jpg|css|js|jpeg|gif|ico|ttf|svg|xml|woff|woff2|ashx|asmx|svc|swf|otf|eot|webp.
        required: false
        default: null
        type: str
      methods_to_bypass:
        description:
          - List the HTTP method to bypass static files with pipe separation. Spaces are not allowed.
          - Default Value:GET|HEAD.
        required: false
        default: null
        type: str
      bypass_when_query_present:
        description:
          - Select to bypass when query is present.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      maximum_request_size:
        description:
          - Enter the maximum request size (in kb).
          - Valid range:1-1024. Default 10.
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
  radware.radware_modules.alteon_config_secure_path_policy:
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
      secure_path_id: 3
      name: secure_path3
      secure_path_policy_state: enabled
      maximum_request_size: 500
      file_extensions_to_bypass: png|jpg
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
from radware.alteon.sdk.configurators.secure_path_policy import SecurePathPolicyConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SecurePathPolicyConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SecurePathPolicyConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    # logging.basicConfig(filename="logSecPath.txt", filemode='a',
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
