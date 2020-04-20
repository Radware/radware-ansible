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
module: alteon_config_high_availability
short_description: Manage High Availability configuration in Radware Alteon
description:
  - Manage High Availability configuration in Radware Alteon 
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
      - Parameters for HA configuration.
    suboptions:
      mode:
        description:
          - Set the high availability mode.
          - Disabled means that High availability is not configured.
          - Switch HA is a switch-based group aggregates all virtual IP addresses on an Alteon as a single entity. The active Alteon supports all traffic or services. The backup Alteon acts as a standby for services on the active master Alteon. If the master Alteon fails, the backup Alteon takes over processing for all services.
          - Service HA is Several VIPs grouped together and behave as a single entity for failover purposes. A service group is comprised of several VIPs and their associated floating IP addresses. You can define up to 64 service groups on a single Alteon platform.
          - Extended HA is an extension of Switch HA mode that enables failover within a cluster of more than two (and up to four) Alteons.
          - Legacy VRRP is A legacy mode that maintains the Alteon high availability module as implemented in software versions earlier than 30.1.
        required: false
        default: null
        choices:
        - disabled
        - vrrp
        - switch
        - service
        - extendedHA
      advertise_bgp_routes_on_backup:
        description:
          - Specifies whether a backup Alteon advertises the virtual IP address (virtual server router) routes to a Border Gateway Protocol peer.
          - This option is intended for cases where bi-directional forwarding (BFD) is activated on BGP peers in a multiple-site topology. 
          - When BGP failure detection is faster than high availability failover, this option prevents the BGP router from redirecting traffic to another site.
          - The backup Alteon advertises its virtual IP addresses, but does not process network traffic for these VIPS until it changes roles from backup to master 
          - (for example, it does not respond to ARPs until it has become active).
          - The purpose of this advertisement is for BGP purposes only, and does not affect Alteon high availability capabilities.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      holdoff_timer_second:
        description:
          - Sets the length of time, in seconds, that the master Alteon waits before forwarding traffic to the default gateway and real servers.
        required: false
        default: 0
        type: int
      send_garp_nwclss_proxy_ips:
        description:
          - Specifies whether to send Gratuitous ARP (GARP) messages for all proxy IP addresses in the network class range.
          - Gratuitous ARP packets are used to force a next-hop router to learn an IP and MAC pair. 
          - For security reasons, this option can only be used for an IP address belonging to a VIP, PIP, or interface.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      advertisement_interval_second:
        description:
          - Sets the length of time, in seconds, between Alteon master advertisements.
        required: false
        default: null
        type: int
      fail_back_mode:
        description:
          - Defines the Alteon failback mode.
          - Onfailure means that failback does not occur if all tracked resources are available on the active Alteon.
          - Always means that failback to the Alteon with preferred state set to active occurs when that Alteon becomes available.
        required: false
        default: onfailure
        choices:
        - onfailure
        - always
      preferred_state:
        description:
          - Defines the Alteon preferred initial state.
          - The preferred initial state is relevant and configurable only when the failback mode is Always.
          - The preferred initial state should be Active for one of the Alteons in an HA pair, and Standby for the other.
          - If both Alteon platforms have the same preferred initial state, the system arbitrarily selects the active Alteon.
        required: false
        default: standby
        choices:
        - active
        - standby
      gateway_tracking_state:
        description:
          - Enable or disable tracking of gateways.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      real_server_tracking_state:
        description:
          - Enable or disable Layer 4 tracking of all real servers.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      sync_dynamic_data_store:
        description:
          - Enable or disable synchronizing the dynamic data store that includes persistence data and/or user-defined dynamic data created and updated via AppShape++ scripts.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      sync_persistent_sessions:
        description:
          - Enable or disable stateful failover for synchronizing the persistent session state.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      sync_session_interval_seconds:
        description:
          - Sets the stateful failover update interval in seconds.
          - The active Alteon sends update packets of new persistent binding entries, if any, to the backup Alteon at the specified update interval.
          - This option available only when the Sync Persistent Sessions checkbox is selected.
        required: false
        default: 30
        type: int
      unicast_session_mirroring:
        description:
          - Enables SFO unicast mode.
          - The Unicast Session Mirroring option enables UDP unicast communication between the active and standby Alteons.
          - You must define the interface over which mirroring takes place.
          - Radware recommends defining a secondary interface for backup. Interfaces used for session mirroring must have a peer IP address configured.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      mirroring_primary_interface:
        description:
          - Sets the primary interface for unicast session failover.
          - You must configure a peer IP address for all IP interfaces participating in session failover.
          - This option is available only when the Unicast Session Mirroring is enabled.
        required: false
        default: null
        type: int
      mirroring_secondary_interface:
        description:
          - Sets the secondary interface for unicast session failover.
          - You must configure a peer IP address for all IP interfaces participating in session failover.
          - This option is available only when the Unicast Session Mirroring is enabled.
        required: false
        default: null
        type: int
      cluster_master_election_priority:
        description:
          - Extended HA mode is an extension of Switch HA mode that enables failover within a cluster of more than two (and up to four) Alteons.
          - There is always a single master in a cluster, based on priority and a Failback/Failover order value, as follows
          - When there is a single Alteon with the highest priority, this Alteon becomes the master. (Priority is not configurable, and is derived from real servers and gateway tracking.)
          - When multiple Alteons share the highest priority, the Alteon among them with the lowest Failback/Failover order value becomes the master.
          - When multiple Alteons share the highest priority and the lowest Failback/Failover order value, there is an internal bidding process that takes place to determine the master.
          - In topologies with multiple Alteon peers, session mirroring should be in broadcast mode, not unicast.
          - To avoid a broadcast storm over the network due to session mirroring, Radware recommends allocating a special VLAN for this purpose.
        required: false
        default: 255
        type: int
      advertising_interfaces:
        description:
          - Sets an IP interface for communication between the Alteon platforms in the HA pair.
          - Make sure that you set a peer IP address for each interface.
          - Radware recommends using more than a single advertisement interface.
        required: false
        default: null
        type: list
        elements: int
      tracked_interfaces:
        description:
          - Select the Layer 3 interface to be tracked.
          - Always enabled.
        required: false
        default: null
        type: list
        elements: int
      tracked_gateways:
        description:
          - Select the gateways to be tracked.
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
  alteon_config_high_availability:
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
      mode: switch
      advertise_bgp_routes_on_backup: enabled
      holdoff_timer_second: 15
      advertisement_interval_second: 2
      fail_back_mode: always
      preferred_state: active
      sync_dynamic_data_store: enabled
      sync_persistent_sessions: enabled
      sync_session_interval_seconds: 20
      unicast_session_mirroring: enabled
      mirroring_primary_interface: 1
      advertising_interfaces:
        - 1
      tracked_interfaces:
        - 1    
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
from radware.alteon.sdk.configurators.high_availability import HighAvailabilityConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(HighAvailabilityConfigurator,  **kwargs)


def main():
    spec = ArgumentSpec(HighAvailabilityConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
