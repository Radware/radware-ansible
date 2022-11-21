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
module: alteon_config_content_rule
short_description: create and manage content base rules for virtual service in Radware Alteon
description:
  - create and manage content base rules for virtual service.
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
      - Parameters for configuring content base rules for virtual service.
    suboptions:
      virtual_server_id:
        description:
          - virtual server id.
        required: true
        default: null
        type: str
      virtual_service_index:
        description:
          - virtual service index.
        required: true
        default: null
        type: int
      content_rule_index:
        description:
          - content rule index.
        required: true
        default: null
        type: int
      rule_name:
        description:
          - the content rule name.
        required: false
        default: null
        type: str
      content_class:
        description:
          - the content class for the rule.
        required: false
        default: null
        type: str
      action:
        description:
          - set action type for this rule.
        required: false
        default: group
        choices:
        - group
        - appredir
        - discard
      group_id:
        description:
          - set real server group number for this rule.
          - set this parameter when when the specified action option is group.
        required: false
        default: null
        type: str
      redirection_url:
        description:
          - set application redirection for this rule.
          - set this parameter when when the specified action option is appredir (redirect).
        required: false
        default: null
        type: str
      state:
        description:
          - Enable or disable Content Based Services Rule.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      bot_manager_processing:
        description:
          - set bot manager processing for this rule.
          - This field is available from alteon versions 33.0.7.0 and 33.5.3.0.
        required: false
        default: inherit
        choices:
        - inherit
        - specific
        - disabled
      bot_manager_policy:
        description:
          - set bot manager policy for this rule..
          - This field is available from alteon versions 33.0.7.0 and 33.5.3.0.
        required: false
        default: null
        type: str
      secure_web_application_processing:
        description:
          - set secured web application processing for this rule.
          - This field is available from alteon version 33.5.3.0.
        required: false
        default: inherit
        choices:
        - inherit
        - disabled
      secure_path_policy:
        description:
          - set secure path policy for this rule..
          - This field is available from alteon version 33.5.3.0.
        required: false
        default: null
        type: str
      sideband_processing:
        description:
          - set sideband processing for this rule.
          - This field is available from alteon version 33.5.3.0.
        required: false
        default: inherit
        choices:
        - inherit
        - specific
        - disabled
      sideband_policy:
        description:
          - set sideband policy for this rule.
          - This field is available from alteon version 33.5.3.0.
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
  radware.radware_modules.alteon_config_content_rule:
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
      virtual_server_id: srvr1
      virtual_service_index: 1
      content_rule_index: 10
      rule_name: myrule
      content_class: test1
      action: group
      group_id: group1
      state: enabled
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
from radware.alteon.sdk.configurators.content_rule import ContentRuleConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(ContentRuleConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(ContentRuleConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    # logging.basicConfig(filename="logCntRule.txt", filemode='a',
    #     format='[%(levelname)s %(asctime)s %(filename)s:%(lineno)s %(funcName)s]\n%(message)s',
    #     level=logging.DEBUG, datefmt='%d-%b-%Y %H:%M:%S')
    # log = logging.getLogger()

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
