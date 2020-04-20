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
module: alteon_config_virtual_service
short_description: Manage virtual service in Radware Alteon
description:
  - Manage virtual service in Radware Alteon.
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
      - Parameters for virtual service configuration.
    suboptions:
      index:
        description:
          - The Virtual Server Index associated with the virtual service.
        required: true
        default: null
        type: str
      service_index:
        description:
          - The Virtual Service Index.
        required: false
        default: ipv4
        type: int
      description:
        description:
          - Virtual Service description.
        required: false
        default: null
        type: str
      service_port:
        description:
          - The Layer 4 port number of the service.
        required: false
        default: null
        type: int
      server_port:
        description:
          - Specifies the Layer 4 TCP or UDP port on which the real servers listen for this service.
          - This parameter must be specified only when all real servers listen for the service on a port that is different from the service port. For all other cases it should be left empty (0).
          - The real server port can alternatively be defined at real server level, allowing for different listening ports per server.
        required: false
        default: 0
        type: int
      protocol:
        description:
          - Defines the Layer 4 protocol for applications that can run on either TCP or UDP. Read-only for applications that only run on a specific Layer 4 protocol.
          - Available protocols vary according to the application selected.
          - C(tcp)-For load balancing a TCP service.
          - C(udp)-For load balancing a UDP service.
          - C(tcpAndUdp)-(Available for IP applications only.) For load balancing TCP and UDP services. When this option is selected, IPsec and ICMP are included in the services to be load balanced.
          - C(stateless)-No session table entry is created. Because no session is created, you have to bind to a new server every time.
        required: false
        default: tcp
        choices:
        - udp
        - tcp
        - stateless
        - tcpAndUdp
      direct_server_return:
        description:
          - Specifies whether to allow the servers to respond directly to the client, without passing through Alteon. This is useful for sites where large amounts of data flow from servers to clients, such as with content providers or portal sites that typically have asymmetric traffic patterns.
          - Direct Server Return allows the server to respond directly to the client, without passing through Alteon. This is useful for sites where large amounts of data flow from servers to clients, such as with content providers or portal sites that typically have asymmetric traffic patterns.
          - When Direct Server Return is enabled, Alteon translates only the destination MAC address to the real server MAC address, and not the destination IP. On the servers you must define a loopback interface with the virtual server IP address.
          - Direct Server Return and content-intelligent Layer 7 load balancing cannot be performed at the same time because content-intelligent load balancing requires that all frames go back to the Alteon for connection splicing.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      persistent_mode:
        description:
          - Specifies the persistence method to be used for this service.
          - Note-Additional persistence methods can be achieved using an AppShape++ script.
          - C(clientip)-Uses the client IP address as the session identifier, and associates all connections from the same client with the same real server until the client becomes inactive, and the persistent entry is aged out of the session table.
          - Different services from the same client may not map to the same server.
          - C(cookie)-Uses a cookie header or a URI cookie as an identifier, and associates all HTTP requests with the same cookie value to the same server.
          - Available only for HTTP and HTTPS (with SSL offload) applications.
          - If the cookie expiration time is greater than the virtual service Persistency Timeout value, timed out requests will not be persistent.
          - C(disabled)-Disables persistence for this service.
          - C(sslid)-Alteon records the SSL session ID and server, and directs all subsequent SSL sessions which present the same session ID to the same real server.
          - Available only for HTTPS and SSL services without SSL offload.
          - Alteon does not support the SSL ID option when you set the virtual service Delayed Binding option to Force Proxy.
        required: false
        default: disabled
        choices:
        - clientip
        - disabled
        - sslid
        - cookie
      cookie_mode:
        description:
          - Specifies the cookie persistence mode.
          - C(rewrite)-The server inserts a persistency cookie in the response but Alteon, and not the network administrator, rewrites it, eliminating the need for the server to generate cookies for each client.
          - C(passive)-The Web server embeds a cookie in its response to the client. Alteon records the specified cookie value and server, and forwards subsequent requests carrying the same cookie value to the same server.
          - Available only for HTTP services and HTTPS services with SSL offload.
          - C(insert)-Alteon generates a cookie value, inserts the Set-Cookie header in the server response, and records the cookie value and the server. All subsequent HTTP requests carrying this cookie value are forwarded to the same server.
          - Available only for HTTP services and HTTPS services with SSL offload (the default persistence type for these services).
        required: false
        default: passive
        choices:
        - rewrite
        - passive
        - insert
      delayed_binding:
        description:
          - Enables or disables Layer 4 delayed binding or full proxy mode for TCP service and ports
          - delayed_binding may automatically set by a feature requires application engine.
          - C(disabled)- Processes traffic at Layer 4 without any interference in the TCP session
          - C(enabled)- Basic delayed binding, until sufficient information is acquired to make a load balancing/routing decision
          - C(forceproxy)- Alteon processes traffic in full proxy mode using the Application Service Engine
        required: false
        default: disabled
        choices:
        - disabled
        - enabled
        - forceproxy
      ssl_policy_name:
        description:
          - Specifies the name of the SSL policy associated with this virtual service.
        required: false
        default: null
        type: str
      server_cert_name:
        description:
          - Specifies the name of the server certificate (single hostname certificate) or certificates group (multiple hostname certificate) associated with this virtual service.
        required: false
        default: null
        type: str
      http_mod_policy_name:
        description:
          - Specify the list of user-defined HTTP modification rules. This enables the flexible configuration of modification rules per virtual service.
        required: false
        default: null
        type: str
      application_type:
        description:
          - The application type for virtual service.
        required: false
        default: basic_slb
        choices:
        - basic_slb
        - dns
        - ftp
        - ftp_data
        - ldap
        - http
        - https
        - ssl
        - rtsp
        - sip
        - wts
        - tftp
        - smtp
        - pop3
        - ip
      service_action:
        description:
          - Sets the action type of this virtual service. When content rules are configured for the service, this parameter specifies the default action when traffic does not match any of the content rules.
        required: false
        default: group
        choices:
        - group
        - redirect
        - discard
      redirect_location:
        description:
          - Sets the application redirection location of this virtual service.
          - The redirection location is a string of up to 255 characters with the following format
          - '<protocol>://<host>[:<port>][/<path>][?<query>]'
          - The protocol and host parameters are mandatory. All other parameters are optional.
        required: false
        default: null
        type: str
      server_cert_type:
        description:
          - Specifies whether a single certificate is used for all hostnames available via this service, or whether each hostname requires a separate certificate.
        required: false
        default: cert
        choices:
        - cert
        - group
      cookie_path:
        description:
          - Specifies the path attribute in the inserted Set-Cookie header. This attribute specifies to the browser whether or not the cookie is valid only for the specific path.
        required: false
        default: null
        type: str
      secure_cookie:
        description:
          - Specifies whether to include or exclude the Secure attribute in the inserted Set-Cookie header. This attribute specifies that the client is required to use a secure connection to obtain content associated with the cookie.
        required: false
        default: no
        choices:
        - no
        - yes
      log_sessions:
        description:
          - Specifies whether to enable or disable session logging.
          - Session logs are sent to the syslog servers via the data port when the sessions are deleted or aged out. The Alteon switch processor sends the buffered session logging data to the syslog server at regular intervals (every 30 seconds) if the buffer is not completely filled. There will be no session syslog if no sessions have aged out during this duration of 30 seconds.
          - Note: Syslog servers configured on Alteon must be accessible via the data ports.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      service_always_on_with_appshape:
        description:
          - Specifies whether a virtual service should always be available, even if all servers are down, when an AppShape++ script is attached to the service. This parameter needs to be enabled only when one of the attached AppShape++ scripts contains treatment for the 'no server available' state (such as returning the Sorry page or redirecting to a special URL).
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      service_down_connection:
        description:
          - Specifies how Alteon handles new connections when a TCP service is unavailable.
          - This parameter can be used only when Delayed Binding is disabled.
        required: false
        default: reset
        choices:
        - reset
        - drop
      cookie_id:
        description:
          - Specifies the name of the cookie whose value is used to select the server.
        required: false
        default: AlteonP
        type: str
      direct_access_mode:
        description:
          - Specifies whether to enable or disable Direct Access Mode (DAM) on this virtual service. This takes precedence when DAM is globally enabled on Alteon.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      x_fwd_for_inject:
        description:
          - Specifies whether to insert an X-Forwarded-For header with the client IP address in HTTP requests. This capability is useful in preserving client IP address information when NAT is performed.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      persistent_server_port:
        description:
          - Specifies whether to use the real server port in the session lookup for a persistent session.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      cookie_insert_domain_name:
        description:
          - Specifies whether to the include or exclude the domain attribute in the inserted Set-Cookie header. This attribute specifies to the browser the domain for which the cookie is valid.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      connection_idle_timeout_minutes:
        description:
          - Specifies the timeout, in minutes, after which an idle server connection is closed. This parameter is relevant only when HTTP multiplexing is performed.
        required: false
        default: 10
        type: int
      server_group_name:
        description:
          - Sets the real server group for this service.
        required: false
        default: 1
        type: str
      session_mirror:
        description:
          - Specifies whether to enable or disable session mirroring on the selected virtual service.
          - Session mirroring synchronizes the state of active connections with the standby Alteon to prevent service interruptions in case of failover.
          - Session mirroring is recommended for long-lived TCP connections, such as FTP, SSH, and Telnet connections. Session mirroring for protocols characterized by short-lived connections such as UDP and in many cases HTTP, is not necessary. Radware recommends that you use session mirroring only when you need to maintain the state of a long connection.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      persistent_timeout_minutes:
        description:
          - Specifies the time, in minutes, after which an inactive persistence entry is removed.
        required: false
        default: 0
        type: int
      nat_mode:
        description:
          - Client NAT specifies whether to translate the source IP to a specified NAT address before forwarding the packet to the server. This capability can be optionally used to hide the original client IP, but it is mandatory in the following cases
          - When client and servers belong to the same IP address space (subnet). By using NAT on the client IP, traffic returning from the server is forced to pass through Alteon.
          - When HTTP multiplexing is enabled.
          - When the clients and servers have different IP versions (IPv4/v6 gateway conversion is performed).
          - When source IP translation is enabled for HTTP or HTTPS with SSL offload service, Alteon enables automatic inserting on the service of an X-Forwarded-For header carrying the original client IP.
          - C(disable)-Do not perform Client NAT for this service.
          - C(ingress)-Perform Client NAT using the NAT (PIP) address configured on the ingress port or VLAN.
          - C(egress)-Perform Client NAT using the NAT (PIP) address configured on the egress port or VLAN.
          - C(address)-Perform Client NAT using the specified NAT (PIP) address and subnet mask (for an IPv4 server) or prefix (for an IPv6 server).
          - C(nwclss)-Perform Client NAT using the specified IPv4 and/or IPv6 network class.
        required: false
        default: ingress
        choices:
        - ingress
        - egress
        - address
        - nwclss
        - disable
      nat_address:
        description:
          - Specifies the Client NAT IPv4 address for the service.
        required: false
        default: null
        type: str
      nat_subnet:
        description:
          - Specifies the subnet mask for the Client NAT IPv4 address for the real server.
        required: false
        default: null
        type: str
      nat6_address:
        description:
          - Specifies the Client NAT IPv6 address for the service.
        required: false
        default: null
        type: str
      nat6_prefix:
        description:
          - Specifies the prefix for the Client NAT IPv6 address for the real server.
        required: false
        default: 128
        type: int
      nat_ip_persistency:
        description:
          - Specifies whether to use the same NAT address for all connections from a specific client IP. This is relevant only when the service NAT address is defined as a subnet or a network class.
        required: false
        default: disable
        choices:
        - disable
        - client
        - host
      nat_network_class_name:
        description:
          - Specifies the Client NAT network class for the real server.
        required: false
        default: null
        type: str
      nat_net_class_ip_persistency:
        description:
          - Specifies whether to use the same NAT address for all connections from a specific client IP. This is relevant only when the service NAT address is defined as a subnet or a network class.
        required: false
        default: disable
        choices:
        - disable
        - client
      close_connection_with_reset:
        description:
          - Specifies whether to reset a connection when a session ages out by sending a TCP RST message.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      cluster_mode:
        description:
          - Enable/Disable service cluster.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      gslb_http_redirect:
        description:
          - GSLB HTTP/S Redirect to remote site
          - Should set to disabled for proxy redirection
        required: false
        default: null
        choices:
        - enabled
        - disabled
      appshapes:
        description:
          - Appshape scripts.
        required: false
        default: null
        elements:
          priority:
            description:
              - Appshape script priority.
            required: true
            type: int
          name:
            description:
              - Appshape script name.
            required: false
            type: str
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_virtual_service:
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
      index: virt_test
      service_index: 1
      service_port: 8080
      server_port: 0
      log_sessions: enabled
      session_mirror: enabled
      service_down_connection: reset
      persistent_timeout_minutes: 30
      close_connection_with_reset: enabled
      direct_server_return: enabled
      application_type: http
      server_cert_name: cert_test
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
from radware.alteon.sdk.configurators.virtual_service import VirtualServiceConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(VirtualServiceConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(VirtualServiceConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
