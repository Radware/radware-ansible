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
module: alteon_config_ha_config_sync
short_description: Radware Alteon HA config sync
description:
  - Radware Alteon HA configuration synchronization 
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
      - Parameters for HA config sync.
    suboptions:
      automatic_sync:
        description:
          - Enable/disable automatic syncing of configuration.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      filter_sync:
        description:
          - Enable/disable syncing filter configuration.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      ip_interface_sync:
        description:
          - Enable/disable syncing IP interface configuration.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      port_sync:
        description:
          - Enable/disable syncing port configuration.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      gateway_sync:
        description:
          - Enable/disable syncing gateways configuration.
        required: false
        default: null
        choices:
          - enabled
          - disabled
      bandwidth_management_sync:
        description:
          - Enable/disable syncing BWM configuration.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      vrrp_sync:
        description:
          - Enable/disable syncing VRRP priorities.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      proxy_ip_sync:
        description:
          - Enable/disable syncing proxy IP addresses.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      peer_proxy_ip_sync:
        description:
          - Enable/disable syncing peer proxy IP addresses.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      static_route_sync:
        description:
          - Enable/disable syncing route table.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      certificate_sync:
        description:
          - Enable/disable syncing certificate repository components.
        required: false
        default: null
        choices:
          - enabled
          - disabled
      mapping_only_sync:
        description:
          - Set sync mapping table only.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      certificate_passphrase:
        description:
          - Set passphrase to encrypt/decrypt synced certificates' private keys.
        required: false
        default: null
        type: str
      peer_authentication_mode:
        description:
          - Select peer authentication mode.
        required: false
        default: null
        choices:
        - admin
        - passphrase
      authentication_passphrase:
        description:
          - Select passphrase to use instead of admin password.
        required: false
        default: null
        type: str
      sync_peers:
        description:
          - Synch Peer Switch Menu.
        required: false
        default: null
        type: list
        elements:
          state:
            description:
              - Sync peer state.
            required: false
            default: null
            choices:
            - enabled
            - disabled
          ip_ver:
            description:
              - IP version.
            required: false
            default: null
            choices:
            - ipv4
            - ipv6
          ip4_address:
            description:
              - IP version.
            required: false
            default: null
            typr: str
          ip6_address:
            description:
              - IP version.
            required: false
            default: null
            type: str
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_ha_config_sync:
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
      automatic_sync: enabled
      filter_sync: enabled
      ip_interface_sync: enabled
      gateway_sync: enabled
      static_route_sync: enabled
      certificate_sync: enabled
      certificate_passphrase: radware
      peer_authentication_mode: passphrase
      authentication_passphrase: radware
      sync_peers:
        - state: enable
            ip_ver: ipv4
            ip4_address: 1.1.1.200
        - state: enable
            ip_ver: ipv4
            ip4_address: 2.2.2.100
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
from radware.alteon.sdk.configurators.ha_configuration_sync import ConfigurationSyncConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(ConfigurationSyncConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(ConfigurationSyncConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

