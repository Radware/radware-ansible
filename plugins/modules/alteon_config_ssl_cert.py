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
module: alteon_config_ssl_cert
short_description: Manage SSL certificates in Radware Alteon
description:
  - Manage SSL certificates in Radware Alteon
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
      - Parameters for SSL certificate configuration.
    suboptions:
      index:
        description:
          - An identifier for a certificate.
        required: true
        default: null
        type: str
      certificate_type:
        description:
          - Certificate type.
        required: true
        default: null
        choices:
        - serverCertificate
        - trustedCertificate
        - intermediateCertificate
      description:
        description:
          - An optional descriptive name of the server certificate in addition to the certificate ID.
        required: false
        default: null
        type: str
      intermediate_ca_name:
        description:
          - The intermediate CA certificate.
        required: false
        default: null
        type: str
      intermediate_ca_type:
        description:
          - Specifies whether an Intermediate CA certificate or certificate chain (group) must be sent to the client together with the server certificate to construct the trust chain to the user's trusted CAs.
        required: false
        default: null
        choices:
        - group
        - cert
      content:
        description:
          - The certificate string.
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
  alteon_config_ssl_cert:
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
      index: test_cert
      certificate_type: serverCertificate
      description: test_cert_desc_2
      content: |
         -----BEGIN CERTIFICATE-----
         MIIDcDCCAligAwIBAgIEXZdR1DANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAl0
         ZXN0X2NlcnQwHhcNMTkxMDA0MTQwNjUxWhcNMjAxMDAzMTQwNjUxWjAUMRIwEAYD
         VQQDDAl0ZXN0X2NlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB
         JWy4t/fI1x1uRQN3ExkMsliT91sUUE8kVtmKnifEUwlg9aCD4c2yGze0KOvx77Qk
         +TJmN/WYh5odTC8+0Z+R4gecDGbF3hCup4PqnGoRkYjqYafLq5ZIGWa5UPQCCjkY
         KnDsDrWJuxjGbDlLUVOqJMBV3gf09c/vqMa0z04LEA+w/d5b3onLw02+v5o+Hcfq
         EgyPFkWEQApo///cwGo9KpuiIfMzkiqxydUHA97aH3pJIdEK6zPhAUdTMw+k6kqM
         rxQ3HDnOTi34Q5WPey7p9MNZt2Qr/hbItD2dQxAugwjfvIGoQBtDfM9Y24/Rs1vy
         pf3EN6hJCXZbrPeZO4WVAgMBAAGjgckwgcYwDwYDVR0TAQH/BAUwAwEB/zARBglg
         hkgBhvhCAQEEBAMCAkQwMwYJYIZIAYb4QgENBCYWJEFsdGVvbi9SYWR3YXJlIEdl
         bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUEKm1R1mLIUN6N3NT1884Vd7N
         4rUwPwYDVR0jBDgwNoAUEKm1R1mLIUN6N3NT1884Vd7N4rWhGKQWMBQxEjAQBgNV
         BAMMCXRlc3RfY2VydIIEXZdR1DALBgNVHQ8EBAMCAuwwDQYJKoZIhvcNAQELBQAD
         ggEBAKl01eJCPprts1MR0ie59w2QDSsQte+No3huCK464mFn5bko/yPB8J8//hrk
         IE1R8pQRskNTPAH98qYevmhu53N8XDzatP63NiJSsXzu6kquEmd2Np/YFbaGa7LP
         qL7GojjADTNYX/O7EPBZfwiQHMEoibvJbOZFT4wWEM2HxoE8spSKzi0beDFKmygp
         On2KHBmdZvlGtygqVnAlkoxIrIgI0bvja9WiG6c/X7McPxi3OB92ap9mbrNlJaj8
         3Rso75dwTVSRtL7ZqiiW7g8pTcBWyy/PZQ7dl+r9m+v6/pe5qjGEmVCBYPM25WC+
         auCiEM/1cKjODR0vsp7nEUwXsdc=
         -----END CERTIFICATE-----
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
from radware.alteon.sdk.configurators.ssl_cert import SSLCertConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SSLCertConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SSLCertConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()