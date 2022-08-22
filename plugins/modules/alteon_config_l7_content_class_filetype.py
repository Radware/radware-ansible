#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, Radware LTD. 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module: alteon_config_l7_content_class_filetype
short_description: create and manage layer7 content class URL filetypes in Radware Alteon
description:
  - create and manage URL filetypes to match in a layer7 content class. 
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
      - Parameters for configuring URL file types to match in layer7 content class.
    suboptions:
      content_class_id:
        description:
          - content class index.
        required: true
        default: null
        type: str
      file_type_entry_id:
        description:
          - file type entry index.
        required: true
        default: null
        type: str
      file_type_to_match:
        description:
          - The URL filetype to match.
        required: false
        default: null
        type: str
      match_type:
        description:
          - Set match type.
        required: false
        default: include
        choices:
        - sufx
        - prefx
        - equal
        - include
        - regex
      case sensitive:
        description:
          - Specifies whether to enable case-sensitivity for string matching.
        required: false
        default: Disable
        choices:
        - Enable
        - Disable
      copy:
        description:
          - Copy the current content class file name entry. Enter the file name ID to which the current host name has to be copied.
        required: false
        default: null
        type: str
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_l7_content_class_filetype:
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
      content_class_id: 3
      file_type_entry_id: filetype1
      file_type_to_match: test_filetype
      match_type: equal
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
from radware.alteon.sdk.configurators.l7_content_class_filetype import L7ContentClassFileTypeConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(L7ContentClassFileTypeConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(L7ContentClassFileTypeConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    #logging.basicConfig(filename="logL7FileType.txt", filemode='a',
    #      format='[%(levelname)s %(asctime)s %(filename)s:%(lineno)s %(funcName)s]\n%(message)s',
    #      level=logging.DEBUG, datefmt='%d-%b-%Y %H:%M:%S')
    #log = logging.getLogger()

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
