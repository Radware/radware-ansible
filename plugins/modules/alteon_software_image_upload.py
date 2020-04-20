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
module: alteo_software_image_upload
short_description: Upload Alteon Image
description:
  - Upload Alteon Software Image on device
  - the command expect src/dst file path
version_added: null
author: 
  - Leon Meguira (@leonmeguira)
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
  file_path:
    description:
      - path to image file
    required: true
    default: null
    type: str
  adc_slot:
    description:
      - adc image slot number
    required: false
    default: null
    type: int
  vx_slot:
    description:
      - vx image slot number, applicable to VX form factor
    required: false
    default: null
    type: int
  password:
    description:
      - upgrade password
    required: false
    default: null
    type: str
  generate_pass:
    description:
      - try to generate upgrade password online if password not provided
    required: false
    default: false
    type: bool
  timeout_seconds:
    description:
      - upload timeout in seconds
    required: false
    default: 300
    type: int
  http_proxy:
    description:
      - http proxy url for generating upgrade password online
    required: false
    default: null
    type: str
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon device software
  alteo_software_image_upload:
    provider: 
      server: 192.168.1.1
      user: admin
      password: admin
      validate_certs: no
      https_port: 443
      ssh_port: 22
      timeout: 5
    vx_slot: 2
    adc_slot: 2
    generate_pass: true
    timeout_seconds: 700
    file_path: /home/user/images/AlteonOS-31-0-10-50_rls_35.img
    http_proxy: http://proxy.example.com:8080
'''

RETURN = r'''
status:
  description: Message detailing run result
  returned: success
  type: str
  sample: Image Uploaded Successfully
'''

from ansible.module_utils.basic import AnsibleModule
import traceback

from ansible.module_utils.network.radware.common import RadwareModuleError
from ansible.module_utils.network.radware.alteon import AlteonManagementModule, AlteonManagementFunctionArgumentSpec
from radware.alteon.sdk.alteon_managment import AlteonMngOper
from ansible.module_utils.basic import env_fallback


class ModuleManager(AlteonManagementModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(AlteonMngOper, command='software_upload', **kwargs)


def main():
    spec = AlteonManagementFunctionArgumentSpec(AlteonMngOper.software_upload)
    spec.argument_spec.update(http_proxy=dict(fallback=(env_fallback, ['http_proxy'])))
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        result['changed'] = True
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
