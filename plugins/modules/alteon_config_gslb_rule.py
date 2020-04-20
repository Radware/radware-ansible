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
module: alteon_config_gslb_rule
short_description: Manage GSLB rule in Radware Alteon
description:
  - Manage GSLB rule in Radware Alteon 
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
      - Parameters for GSLB rule configuration.
    suboptions:
      index:
        description:
          - Rule ID.
        required: true
        default: null
      state:
        description:
          - Rule state.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      dns_ttl:
        description:
          - Time To Live in seconds of DNS resource records.
        required: false
        default: null
        type: int
      max_dns_resource_records:
        description:
          - DNS resource records in DNS response.
        required: false
        default: null
        type: int
      domain_name:
        description:
          - Network preference domain name for rule.
        required: false
        default: null
        type: str
      src_dns_persist_mask:
        description:
          - Source IP subnet mask for DNS persistence cache.
        required: false
        default: null
        type: str
      dns_persist_timeout:
        description:
          - Timeout in minutes for DNS persistence cache.
        required: false
        default: null
        type: int
      src6_dns_persist_prefix:
        description:
          - Source IPv6 prefix for DNS persistence cache.
        required: false
        default: null
        type: int
      rule_type:
        description:
          - DNS redirection rule type.
        required: false
        default: null
        choices:
        - gslb
        - inboundllb
      description:
        description:
          - Descriptive rule name.
        required: false
        default: null
        type: str
      edns_persist_mode:
        description:
          - Enable/disable use of EDNS value for DNS persistency.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      rule_network_fallback:
        description:
          - Enable/disable network metric fallback.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      rule_metrics:
        description:
          - Rule metrics.
        required: false
        default: null
        elements:
          priority:
            description:
              - Rule metric priority.
            required: true
            type: int
          metric:
            description:
              - GSLB rule metric.
            required: true
            choices:
            - leastconns
            - roundrobin
            - response
            - geographical
            - network
            - random
            - availability
            - qos
            - minmisses
            - hash
            - local
            - always
            - remote
            - none
            - persistence
            - phash
            - proximity
            - bandwidth
            - absleastconn
          network_ids:
            description:
              - network to metric=network.
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
  alteon_config_gslb_rule:
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
      index: 55
      state: enabled
      dns_ttl: 180
      description: test_rule
      edns_persist_mode: enabled
      domain_name: www.test.com
      max_dns_resource_records: 3
      rule_metrics:
        first:
          metric: network
          network_ids:
            - 55
            - 56
        second:
          metric: absleastconns                  
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
from radware.alteon.sdk.configurators.gslb_rule import GSLBRuleConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(GSLBRuleConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(GSLBRuleConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

