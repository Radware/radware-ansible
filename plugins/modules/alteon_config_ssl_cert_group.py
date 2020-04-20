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
module: alteon_config_ssl_cert_group
short_description: Manage SSL certificate groups in Radware Alteon
description:
  - Manage SSL certificate groups in Radware Alteon
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
      - Parameters for SSL certificate configuration.
    suboptions:
      index:
      description:
        - Certificate group ID.
      required: true
      default: null
      type: str
      certificate_type:
      description:
        - Certificate type.
      required: false
      default: null
      choices:
      - serverCertificate
      - trustedCertificate
      - intermediateCertificate
      description:
      description:
        -  Certificate group description.
      required: false
      default: null
      type: str
      default_server_certificate:
      description:
        - Default server certificate, applicable to certificate_type=serverCertificate.
      required: false
      default: null
      type: str
      certificate_chaining_mode:
      description:
        - Certificate chaining mode.
      required: false
      default: null
      choices:
      - bySubjectIssuer
      - bySkidAkid
      certificate_names:
      description:
        - Certificate names belong to group.
      required: false
      default: null
      type: list
      elements: str
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
    alteon_config_ssl_cert_group:
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
      index: test_cert_group
      certificate_type: serverCertificate
      description: test cert group
      default_server_certificate: test
      certificate_names:
      - test
      - test_2
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
from radware.alteon.sdk.configurators.ssl_cert_group import SSLCertGroupConfigurator


class ModuleManager(AlteonConfigurationModule):
  def __init__(self, **kwargs):
    super(ModuleManager, self).__init__(SSLCertGroupConfigurator, **kwargs)


def main():
  spec = ArgumentSpec(SSLCertGroupConfigurator)
  module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

  try:
    mm = ModuleManager(module=module)
    result = mm.exec_module()
    module.exit_json(**result)
  except RadwareModuleError as e:
    module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
  main()
