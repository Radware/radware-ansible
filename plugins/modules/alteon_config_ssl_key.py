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
module: alteon_config_ssl_key
short_description: Manage SSL key in Radware Alteon
description:
  - Manage SSL key in Radware Alteon
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
      - Parameters for SSL key configuration.
    suboptions:
      index:
        description:
          - An identifier for a key.
        required: true
        default: null
        type: str
      description:
        description:
          - An optional descriptive name of the server certificate in addition to the certificate ID.
        required: false
        default: null
        type: str
      passphrase:
        description:
          - The passphrase that decrypts the private key.
        required: false
        default: null
        type: str
      content:
        description:
          - The key string.
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
  alteon_config_ssl_key:
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
      passphrase: password
      description: test_cert_desc_2
      content: |
         -----BEGIN RSA PRIVATE KEY-----
         Proc-Type: 4,ENCRYPTED
         DEK-Info: DES-EDE3-CBC,2533C0E93A066F6C
         
         ZqomWJ2FWCyug2iccbtEK0jAOU153qEaUiAhMy9rraX3YZd8hYzu/b4VcomUmosR
         bPI5stcKTk41hwLfPFilwWeBtRJ5n5Sp/bxsNH+jHbujloVog4jXjllsp1gndjSq
         am0wRkolVO6vQ2+aHIFgEla+9igW3YMCNKwAp/Jgu1CS9ThtEfr9cifZlpzJmAvR
         PrjilSUFf/XeR9DUhiDeYdlerA6uslQr85o2BiNshV6Q3338Q2wMvNwEEIVsIRFd
         GrdWEl33YyHxSTQID0UDNzcm+u3ioTdPpu7nmXV716UMJWC9JnRAPcZJTvzAbRol
         ktBvpOfyHqlcD+eLmKuM/tBOt4ylGM7KmwiF/S9PU4+KmHvdrFhg2f8Xtg1ZdA61
         nZjlhAvZe60t/KAlKHxG+5N3BHnQnEGg+rY+Uc6w9lV3fZJrgnG8EGQ8oGZaavuw
         khVuAFHw0mOKZCmqBXVzBquNXFb/iuCsf6nz3OWe9fQtncGndyT6NVgYjEkxUxqV
         103CXKtTl6Ign6XHFWYZlz0GEaft9a5AYmzwm+ei08BZQHS0mwNCoMZjhxtQxGme
         xsyuS19J5DFYsKzTrLBNLlVFI90j0FnJDwYcTrKg8IsdDYp6hJbYXIm13cFUvoGw
         bSa9T1wCTWv8zu+CTwmKyP4AUuMVJdd7WFAC4SofkBUw+f5KHtgac2WPHlJxEK4E
         /0j26j7i4dCIq36F4KZsBCbE+BiG2C9BruvGkXRDhQzN9oSvDou6gzLDb+PtVOwW
         WTF+YDUkM3RowHPvGlvGYx7JUT7ibbF3ZFj3lUhzscTRoMZTSZTcOdXq19RB8Ibe
         WvrdBLWoINn8SvvGRfL78IEpjTSTB9IXslAYRY6OZcyfFwk3GsTJc14Yh3BT2+Jw
         tQwF7ho+9j84pTV5PITAE69oXxJ5rWldAvbW5Py1sV16XWXa9jb8xxXM90rOZpRd
         pIPP1TUbXAJsZFOjfsqTfjPfnkxYLqYoC3KySVBx2kyhA9LiOx8da0LdCfA2yWN/
         lTPbmgkoOpGO5WZ/wc9FD3xWg1QTJpa5UeNz5oeXV/tR3wVXGlvyj6oOt0hHvo2G
         +CPGiUixmz4Fa3cu4IDWfjQAvEgNsgSfBasxT8+7iPuE/dDjHx7qD0sfUWkzlze1
         YUApufwJsOVRMPMFoz/RINnmNikync7n4xX2mWez23g9Ej0HqG4xrpIY53OngZgF
         hYZL1rhfGU9uUdk/CegF3kgqHH6ekAFZbhZ1kMEeqJO/+ddnJBuJwN/o3yN6uF08
         kc3phjvyGxdx+j+vF5BXKw6gS/LL/0BbHg0ONpXjUS8en3wVxMe+GPFr6gU7Z/Kl
         oJTP49OBNHfxBrGaFhS/SbF835krq2/XcoL1hp9A3ljiyURvMFzEX1GElFWsnlA4
         X7Chp+wrD0Z+xrYUQ/SWnyLBuEBl64OX8U5jepr0h0Lhn7sdeHanId0z5yEFtxZZ
         elQ+8SLyxtDpiDMPkm+qM3wKIuz8d3+bYDGBbuRrXTJOKVcv5e2l+zSDOO+xVD+i
         cQr4lJWKAPRM3Hdy2R86cj8+3l8vEaaoh+YVuDWM1o1c+Sze+7vH2LvcuNjxyqHa
         -----END RSA PRIVATE KEY-----
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
from radware.alteon.sdk.configurators.ssl_key import SSLKeyConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SSLKeyConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SSLKeyConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
