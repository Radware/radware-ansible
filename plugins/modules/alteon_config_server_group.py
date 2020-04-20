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
module: alteon_config_server_group
short_description: Manage server group in Radware Alteon
description:
  - Manage server group in Radware Alteon
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
      - Parameters for server group configuration.
    suboptions:
      index:
        description:
          - Group ID.
        required: true
        default: null
        type: str
      slb_metric:
        description:
          - The metric used to select next server in the group.
          - In C(leastConnections), Alteon sends the incoming connections to the real port with the least number of connections.
          - In C(roundRobin), when an available server is selected, Alteon ensures even distribution when choosing a real port to receive the incoming connection.
          - C(minMisses) is optimized for cache redirection. Alteon calculates a value for each available real server based on the relevant IP address information in the client request. The server with the highest value is assigned the connection. This metric attempts to minimize the disruption of persistence when servers are removed from service. Use only when persistence is required.
          - In C(response), Alteon uses the response time between itself and real servers as a weighting factor. Alteon monitors and records the amount of time it takes for each real server to reply to a health check to adjust the real server weights. The weights are adjusted so they are inversely proportional to a moving average of response time. In such a scenario, a server with half the response time as another server receives a weight twice as large.
          - In C(bandwidth), Alteon monitors the number of octets sent between itself and real servers. Servers that process more octets are considered to have less available bandwidth. Alteon assigns requests client requests to the server with the greatest available bandwidth. When the upload and download bandwidths are configured for WAN link groups, Alteon calculates the server bandwidth based on bandwidth utilization, not on octets.
          - In C(hash), Alteon selects the real server based on a hash of the client IP address.
          - In C(phash), Alteon selects the real server based on a hash of the client IP address. With Persistent Hash enabled, Alteon supports an even load distribution (Hash) and stable server assignment (Minmiss) even when a server in the group goes down. With the Persistent Hash metric, the first hash always is the same even if a real server is down. If the first hash hits an unavailable server, Alteon rehashes the client request based on the actual number of servers available. This results in a request always being sent to a server that is available.
          - In C(svcLeast), Alteon selects the real server based only on the number of active connections for the service which is load balanced, and not the total number of connections active on the server. For example, when selecting a real server for a new HTTP session, a real server serving one HTTP connection and 20 FTP connections takes precedence over a real server serving two HTTP connections only.
        required: false
        default: leastConnections
        choices:
        - roundRobin
        - leastConnections
        - minMisses
        - hash
        - response
        - bandwidth
        - phash
        - svcLeast
      slb_rport_metric:
        description:
          - Specifies how a specific service instance (port) is selected on a real server when multiple service ports are configured on that real server.
        required: false
        default: roundRobin
        choices:
        - roundRobin
        - hash
        - leastConnections
      backup_server_name:
        description:
          - The backup real server for this group.
        required: false
        default: null
        type: str
      backup_group_name:
        description:
          - The backup real server group for this group.
        required: false
        default: null
        type: str
      secondary_backup_group_name:
        description:
          - The secondary backup real server group for this group.
        required: false
        default: null
        type: str
      backup_type:
        description:
          - The real server or real server group used as the backup or overflow server or server group for this real server group.
          - You can assign a backup real server or real server group to prevent loss of service if the entire real server group fails.
          - If the real server group becomes unavailable, Alteon activates the backup real server or real server group until one of the original real servers becomes available again.
          - The backup server or real server group is also used in overflow situations. If all the servers in the real server group reach their maximum connections limit, Alteon activates the backup server or real server group to provide additional processing power until resources become available on one of the original servers.
          - You can assign the same backup real server or real server group to more than one real server group at the same time.
        required: false
        default: none
        choices:
        - none
        - server
        - group
      vip_health_check_mode:
        description:
          - The real server or real server group used as the backup or overflow server or server group for this real server group.
          - You can assign a backup real server or real server group to prevent loss of service if the entire real server group fails.
          - If the real server group becomes unavailable, Alteon activates the backup real server or real server group until one of the original real servers becomes available again.
          - The backup server or real server group is also used in overflow situations. If all the servers in the real server group reach their maximum connections limit, Alteon activates the backup server or real server group to provide additional processing power until resources become available on one of the original servers.
          - You can assign the same backup real server or real server group to more than one real server group at the same time.
        required: false
        default: none
        choices:
        - none
        - server
        - group
      persist_hash_mask:
        description:
          - Specifies whether Alteon hashes the client IP address or network for the persistent hash selection.
        required: false
        default: 255.255.255.255
        type: str
      slow_start_time_second:
        description:
          - Specifies the slow start time, in seconds, for this server group.
          - The slow start time is the interval between the time at which the server is identified as up, and the time at which the server is considered part of the server group.
        required: false
        default: 0
        type: int
      ip_ver:
        description:
          - The IP version type of the real server group IP address.
        required: false
        default: ipv4
        choices:
        - ipv4
        - ipv6
        - mixed
      health_check_id:
        description:
          - Select a predefined or user-defined health check.
        required: false
        default: tcp
        type: str
      group_server_type:
        description:
          - The server group type.
        required: false
        default: local
        choices:
        - local
        - wanlink
      persist_overload_max_conn_server:
        description:
          - Specifies whether to ignore the overflow/overload server status, under certain conditions.
          - When enabled, new connections are allocated to a server for which the maximum connections limit has been reached (overflow) or which is in overloaded status as a result of a health check, if the new connections belong to existing persistent sessions on that server (with Persistency Mode set to Client IP, SSL ID, or Cookie).
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      server_names:
        description:
          - Group members
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
  alteon_config_server_group:
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
      index: group_test
      slb_metric: bandwidth
      health_check_id: test_hc
      slow_start_time_second: 60
      persist_overload_max_conn_server: enabled
      server_names:
        - server1
        - server2  
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
from radware.alteon.sdk.configurators.server_group import ServerGroupConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(ServerGroupConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(ServerGroupConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
