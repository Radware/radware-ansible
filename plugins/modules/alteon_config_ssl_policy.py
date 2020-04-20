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
module: alteon_config_ssl_policy
short_description: Manage SSL policy in Radware Alteon
description:
  - Manage SSL policy in Radware Alteon
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
      - Parameters for SSL policy configuration.
    suboptions:
      index:
        description:
          - The SSL policy name as an index.
        required: true
        default: null
        type: str
      description:
        description:
          - A name or description for the SSL policy.
        required: false
        default: null
        type: str
      state:
        description:
          - Enable/Disable the SSL policy.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      secure_renegotiation:
        description:
          - Specifies the maximum number of allowed secure renegotiations.
          - 0 (secure renegotiation is disabled on both front-end and back-end servers).
          - 1 to 1024.
          - unlimited (unlimited secure renegotiation is enabled).
        required: false
        default: 5
        type: int
      dh_key_size:
        description:
          - A specific method of securely exchanging cryptographic keys over a public channel.
        required: false
        default: keySize2048
        choices:
        - keySize1024
        - keySize2048
      fe_ssl_encryption:
        description:
          - Specifies whether to establish an SSL connection with the client and allow decryption/encryption of client traffic.
          - C(disabled) No decryption/encryption on the client-side connection.
          - C(enabled) The SSL connection is established and traffic is decrypted/encrypted on the client-side connection
          - C(connect) he SSL connection is established after clear-text HTTP Connect request is received and answered. This option is relevant only for outbound SSL Inspection scenarios where Alteon is installed as the HTTPS proxy for the clients.
          - For other (non-HTTP) traffic, the SSL connection is established a after clear-text "starttls" request is received and answered.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
        - connect
      fe_ssl_v3:
        description:
          - Enable/Disable SSLv3 during SSL/TLS handshake.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      fe_ssl_tls1_0:
        description:
          - Enable/Disable TLS 1.0 during SSL/TLS handshake.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      fe_ssl_tls1_1:
        description:
          - Enable/Disable TLS 1.1 during SSL/TLS handshake.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      fe_ssl_tls1_2:
        description:
          - Enable/Disable TLS 1.2 during SSL/TLS handshake.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      fe_cipher_suite:
        description:
          - Select the cipher suite to use during SSL handshake. By default, the RSA cipher suite is selected.
          - Radware recommends that you use the PCI-DSS predefined cipher suite for enhanced SSL security.
        required: false
        default: main
        choices:
        - rsa
        - all
        - all_non_null_ciphers
        - sslv3
        - tlsv1
        - tlsv1_2
        - export
        - low
        - medium
        - high
        - rsa_rc4_128_md5
        - rsa_rc4_128_sha1
        - rsa_des_sha1
        - rsa_3des_sha1
        - rsa_aes_128_sha1
        - rsa_aes_256_sha1
        - pci_dss_compliance
        - user_defined
        - user_defined_expert
        - main
        - http2
      fe_user_defined_cipher:
        description:
          - The user-defined cipher-suite allowed for SSL, in OpenSSL format.
          - Alteon supports all ciphers supported by the OpenSSL format.
        required: false
        default: null
        type: str
      fe_intermediate_ca_chain_name:
        description:
          - Specifies the Intermediate CA certificate name or certificate chain (group) to be sent to the client together with the server certificate to construct the trust chain to the user's trusted CAs.
        required: false
        default: null
        type: str
      fe_intermediate_ca_chain_type:
        description:
          - Specifies the Intermediate CA certificate or certificate chain (group) to be sent to the client together with the server certificate to construct the trust chain to the user's trusted CAs.
        required: false
        default: null
        choices:
        - group
        - cert
      fe_auth_policy_name:
        description:
          - Specifies how client certificate authenticity should be checked, if at all.
        required: false
        default: null
        type: str
      fe_hw_ssl_offload:
        description:
          - Specifies enabling hardware offload on the front-end SSL.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      fe_hw_offload_rsa:
        description:
          - Specifies enabling hardware offload for RSA algorithm on the front-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      fe_hw_offload_dh:
        description:
          - Specifies enabling hardware offload for DHE algorithm on the front-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      fe_hw_offload_ec:
        description:
          - Specifies enabling hardware offload for ECDHE algorithm on the front-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      fe_hw_offload_bulk_encryption:
        description:
          - Specifies enabling hardware offload for Bulk encryption algorithm on the front-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      be_ssl_encryption:
        description:
          - Specifies whether to establish an SSL connection towards the server and allow decryption/encryption of client traffic.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      be_ssl_v3:
        description:
          - Enable/Disable SSLv3 during SSL/TLS handshake.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      be_ssl_tls1_0:
        description:
          - Enable/Disable TLS 1.0 during SSL/TLS handshake.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      be_ssl_tls1_1:
        description:
          - Enable/Disable TLS 1.1 during SSL/TLS handshake.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      be_ssl_tls1_2:
        description:
          - Enable/Disable TLS 1.2 during SSL/TLS handshake.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      be_cipher:
        description:
          - Specifies the cipher suites allowed in the back-end SSL policy.
        required: false
        default: main
        choices:
        - low
        - medium
        - high
        - user_defined
        - user_defined_expert
        - main
      be_user_defined_cipher:
        description:
          - Specifies a user-defined cipher-suite using an exact cipher-string (requires expert OpenSSL knowledge).
        required: false
        default: null
        type: str
      be_client_cert_name:
        description:
          - Specifies the client certificate that should be used when the server requests from the client (Alteon) certificate for authentication.
        required: false
        default: null
        type: str
      be_auth_policy_name:
        description:
          - Specifies how server certificate authenticity should be checked, if at all. Select an Authentication Policy of type Server.
        required: false
        default: null
        type: str
      be_include_sni:
        description:
          - Specifies whether to enable or disable including back-end SNI.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      be_hw_offload_rsa:
        description:
          - Specifies enabling hardware offload for RSA algorithm on the back-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      be_hw_offload_dh:
        description:
          - Specifies enabling hardware offload for DHE algorithm on the back-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      be_hw_offload_ec:
        description:
          - Specifies enabling hardware offload for ECDHE algorithm on the back-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      be_hw_offload_bulk_encryption:
        description:
          - Specifies enabling hardware offload for Bulk encryption algorithm on the back-end SSL.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      be_hw_ssl_offload:
        description:
          - Specifies enabling hardware offload on the back-end SSL.
        required: false
        default: enabled
        choices:
        - enabled
        - disabled
      pass_ssl_info_cipher_header_name:
        description:
          - Specifies what header name to use when passing cipher-suite information to the back-end servers.
        required: false
        default: Cipher-Suite
        type: str
      pass_ssl_info_cipher_header:
        description:
          - Specifies whether to pass cipher-suite information to the back-end servers.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      pass_ssl_info_ssl_ver_header_name:
        description:
          - Specifies what header name to use when passing the SSL version to the back-end servers to the back-end servers.
        required: false
        default: SSL-Version
        type: str
      pass_ssl_info_ssl_ver:
        description:
          - Specifies whether to pass the SSL version to the back-end servers.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      pass_ssl_info_cipher_bits_header_name:
        description:
          - Specifies what header name to use when passing the key length for the symmetric cipher negotiated (for example, 128 bits if AES128 was selected) to the back-end servers.
        required: false
        default: Cipher-Bits
        type: str
      pass_ssl_info_cipher_bits_header:
        description:
          - Specifies whether to pass the key length for the symmetric cipher negotiated (for example, 128 bits if AES128 was selected) to the back-end servers.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      pass_ssl_info_add_front_end_https_header:
        description:
          - Specifies whether to add the Front-End HTTPS header to communicate to the back-end servers that the connection from the client is over HTTPS.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      pass_ssl_info_compliant_x_ssl_header:
        description:
          - Specifies whether to enable the 2424SSL Headers Compliance Mode.
        required: false
        default: disabled
        choices:
        - enabled
        - disabled
      http_redirection_conversion:
        description:
          - Enable/Disable HTTP redirection conversion
        required: false
        choices:
        - enabled
        - disabled
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon configuration command
  alteon_config_ssl_policy:
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
      index: ssl_pol_test
      description: test_policy
      be_ssl_encryption: enabled
      secure_renegotiation: 3
      fe_cipher_suite: user_defined_expert
      fe_user_defined_cipher: ALL:!DH:!NULL:!aNULL:!EXPORT:!RC4:!RC2:!3DES:!DES:!DSS:!SRP:!PSK:!IDEA:!SSLv2:!RSA:@STRENGTH
      be_hw_offload_rsa: disabled
      pass_ssl_info_add_front_end_https_header: enabled
      fe_intermediate_ca_chain_type: group
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
from radware.alteon.sdk.configurators.ssl_policy import SSLPolicyConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SSLPolicyConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SSLPolicyConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
