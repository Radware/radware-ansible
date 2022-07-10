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
module: alteon_config_bgp_peer
short_description: create and manage BGP peer in Radware Alteon
description:
  - create and manage BGP peer in Radware Alteon. 
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
      - Parameters for BGP peer configuration.
    suboptions:
      index:
        description:
          - peer ID.
        required: true
        default: null
        type: int
      remote_addr:
        description:
          - The remote IP address of the BGP peer.
        required: false
        default: null
        type: str
      remote_as_number:
        description:
          - Set the remote automonos system (AS) number of the BGP peer using plain notation. 0 means none.
          - Use either this or remote_asdot_number (as asdot notation), but not both.
        required: false
        default: null
        type: int
      remote_asdot_number:
        description:
          - Set the remote automonos system (AS) number of the BGP peer, using asdot notation.
          - Use either this or remote_as_number (as plain notation), but not both.
          - thia field is available from alteon versions: 33.0.5.0 and 33.5.1.0
        required: false
        default: null
        type: str
      ttl:
        description:
          - The time-to-live value in seconds of the BGP peer IP datagram.
        required: false
        default: 1
        type: int
      state:
        description:
          - Enable or disable the peer.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      advertised_route_metric:
        description:
          - Set default-metric of advertized routes.
        required: false
        default: null
        type: int
      default_route_action:
        description:
          - Set the value of default route action.
        required: false
        default: none
        choices:
        - none
        - import_
        - originate
        - redistribute
      advertising_ospf_routes:
        description:
          - Enable or disable advertising OSPF routes.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      advertising_fixed_routes:
        description:
          - Enable or disable advertising fixed routes.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      advertising_static_routes:
        description:
          - Enable or disable advertising static routes.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      advertising_vip_routes:
        description:
          - Enable or disable advertising VIP routes.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      hold_time:
        description:
          - Specifies the period of time in seconds that will elapse before the
          - peer session is torn down because Alteon has not received a Keep-Alive
          - message from the peer.
        required: false
        default: 180
        type: int
      keep_alive_time:
        description:
          - The keep-alive time value in seconds of the BGP peer IP datagram.
        required: false
        default: 60
        type: int
      min_adv_time:
        description:
          - Specifies the minimum time in seconds between advertisements of the BGP peer IP datagram.
        required: false
        default: 60
        type: int
      connect_retry_interval:
        description:
          - Specifies the connection retry interval in seconds of the BGP peer IP datagram.
        required: false
        default: 120
        type: int
      min_as_origination_interval:
        description:
          - Specifies the minimum time in seconds between route originations of the BGP peer IP datagram.
        required: false
        default: 30
        type: int
      advertising_rip_routes:
        description:
          - Enable or disable advertising RIP routes.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      advertising_deny_routes:
        description:
          - Enable or disable advertising deny routes.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      next_hop_addr:
        description:
          - The IP address that Alteon advertises to BGP peers.
        required: false
        default: null
        type: str
      bfd:
        description:
          - Enable or disable Bidirectional Forwarding Detection (BFD).
        required: false
        default: off
        choices:
        - on
        - off
      ip_version:
        description:
          - The IP address version of the BGP peer address.
        required: false
        default: ipv4
        choices:
        - ipv4
        - ipv6
      remote_ipv6_addr:
        description:
          - The remote IPv6 address of the BGP peer.
        required: false
        default: null
        type: str
      in_rmap_list:
        description:
          - Add or remove route map to the incoming route map list.
        required: false
        default: null
        type: list
        elements: int
      out_rmap_list:
        description:
          - Add or remove route map to the outgoing route map list.
        required: false
        default: null
        type: list
        elements: int
      graceful_restart_status:
        description:
          - Enable or disable graceful restart for the peer.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      standard_community_advertisement_status:
        description:
          - Enable or disable advertising Standard community attribute.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      large_community_advertisement_status:
        description:
          - Enable or disable advertising large community attribute.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      extended_community_advertisement_status:
        description:
          - Enable or disable advertising extended community attribute.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      ttl_security_hops:
        description:
          - Set ttl security hops count.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: 30
        type: int
      peer_password:
        description:
          - set authentication password.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: null
        type: str
      password_status:
        description:
          - Enable or disable using authentication password.
          - This field is can be configured only when BGP global mode is FRR.
          - This field is can not be configured on VADC instance.
        required: false
        default: null
        choices:
        - enabled
        - disabled
notes:
  - Requires the Radware alteon-sdk Python package on the host. This is as easy as
      C(pip3 install alteon-sdk)
requirements:
  - alteon-sdk
'''

EXAMPLES = r'''
- name: alteon configuration command
  radware.radware_modules.alteon_config_bgp_peer:
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
      index: 3
      state: enabled
      remote_addr: 3.3.3.3
      in_rmap_list: 
      - 1
      - 2
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
from radware.alteon.sdk.configurators.bgp_peer import BgpPeerConfigurator

class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(BgpPeerConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(BgpPeerConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
