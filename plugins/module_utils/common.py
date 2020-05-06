from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.basic import AnsibleModule
from abc import ABCMeta, abstractmethod
try:
    from radware.sdk.common import RadwareParametersStruct, RadwareParametersExtension, \
        PasswordArgument, get_annotation_class, is_annotation_type_optional, is_annotation_type_list, \
        is_optional_type_list, get_type_hints
    from radware.sdk.beans_common import BaseBeanEnum
    from radware.sdk.api import BaseDeviceConnection
    from radware.sdk.management import DeviceManagement
except ModuleNotFoundError:
    AnsibleModule(argument_spec={}, check_invalid_arguments=False).fail_json(
        msg="The radware-sdk-common package is required")


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
module:
author:
  - Leon Meguira (@leonmeguira)
'''

https_server_spec = {
    'https_port': dict(
        required=False,
        type='int',
        fallback=(env_fallback, ['RADWARE_HTTPS_PORT']),
        default=443
    ),
    'validate_certs': dict(
        required=False,
        type='bool',
        fallback=(env_fallback, ['RADWARE_VALIDATE_CERTS']),
        default=True
    ),
}

ssh_server_spec = {
    'ssh_port': dict(
        required=False,
        type='int',
        fallback=(env_fallback, ['RADWARE_SSH_PORT']),
        default=22
    )
}

radware_provider_spec = {
    'server': dict(
        required=True,
        fallback=(env_fallback, ['RADWARE_SERVERS'])
    ),
    'timeout': dict(
        required=False,
        type='int',
        fallback=(env_fallback, ['RADWARE_TIMEOUT']),
        default=20
    ),
    'user': dict(
        required=True,
        fallback=(env_fallback, ['RADWARE_USER'])
    ),
    'password': dict(
        required=True,
        no_log=True,
        aliases=['pass', 'pwd'],
        fallback=(env_fallback, ['RADWARE_PASSWORD'])
    ),
}

radware_vdirect_workflow_provider = {
    'workflow': dict(
        required=False
    )
}

radware_server_spec = {}
radware_server_spec.update(radware_provider_spec)
radware_server_spec.update(ssh_server_spec)
radware_server_spec.update(https_server_spec)

radware_vdirect_workflow_spec = {}
radware_vdirect_workflow_spec.update(radware_provider_spec)
radware_vdirect_workflow_spec.update(radware_vdirect_workflow_provider)
radware_vdirect_workflow_spec.update(https_server_spec)

workflow_argument_spec = {
    'workflow': dict(
        required=False),
    'action': dict(
        required=False)
}

radware_server_argument_spec = {
    'provider': dict(
        type='dict',
        options=radware_server_spec)
}

radware_vdirect_argument_spec = {
    'provider': dict(
        type='dict',
        options=radware_vdirect_workflow_spec)
}


class AnsibleRadwareParameters(object):
    def __init__(self, **params):
        self._params = params

    def build(self):
        self.__dict__.update(self._params)
        return self


def load_params(params):
    provider = params.get('provider') or dict()
    for key, value in provider.items():
        if key in radware_provider_spec:
            if params.get(key) is None and value is not None:
                params[key] = value


class RadwareBaseModule(object):
    def __init__(self, **kwargs):
        self.module = kwargs.get('module')
        self.params = self.module.params
        self.provider = self.params.get('provider')


class BaseAPI(object):
    __metaclass__ = ABCMeta

    @property
    @abstractmethod
    def _base(self) -> RadwareBaseModule:
        pass

    @property
    @abstractmethod
    def _device_connection(self) -> BaseDeviceConnection:
        pass

    @property
    @abstractmethod
    def _device_mng(self) -> DeviceManagement:
        pass


def build_specs_from_annotation(annotations_src_object):
    # generate Ansible argument specs dict for input validation
    # type and other attributed are consumed from Parameter object metadata
    # the operation is performed recursively

    specs = dict()
    annotations = get_type_hints(annotations_src_object)
    for k, v in annotations.items():
        list_mode = False
        new_spec_item = dict()
        annotation_class = get_annotation_class(annotations[k])
        if is_annotation_type_optional(annotations[k]):
            new_spec_item.update(dict(required=False))
            if is_optional_type_list(annotations[k]):
                new_spec_item.update(dict(type='list'))
                list_mode = True
        else:
            new_spec_item.update(dict(required=True))

        if is_annotation_type_list(annotations[k]):
            new_spec_item.update(dict(type='list'))
            list_mode = True

        if issubclass(annotation_class, RadwareParametersStruct):
            if list_mode:
                new_spec_item.update(dict(elements='dict'))
            else:
                new_spec_item.update(dict(type='dict'))
            new_spec_item.update(dict(options=build_specs_from_annotation(
                annotation_class)))
        else:
            if annotation_class == PasswordArgument:
                new_spec_item.update(dict(no_log=True))
            if annotation_class == int or annotation_class == bool:
                if list_mode:
                    new_spec_item.update(dict(elements=annotation_class.__name__))
                else:
                    new_spec_item.update(dict(type=annotation_class.__name__))
            else:
                if issubclass(annotation_class, BaseBeanEnum):
                    if list_mode:
                        raise TypeError('ArgumentSpecs: Enum class {0} not allowed with type=list'.format(
                            annotation_class))
                    new_spec_item.update(dict(choices=annotation_class.value_names()))
                elif issubclass(annotation_class, RadwareParametersExtension):
                    if list_mode:
                        raise TypeError('ArgumentSpecs: RadwareParametersExtension class {0} not allowed with '
                                        'type=list'.format(annotation_class))
                    val_options = list()
                    for name, val in annotation_class.__dict__.items():
                        if not name.startswith('_'):
                            val_options.append(val)
                    new_spec_item.update(dict(choices=val_options))
                elif annotation_class != str and annotation_class != PasswordArgument:
                    raise TypeError('ArgumentSpecs: unsupported argument type {0}'.format(annotation_class))

        specs.update({k: new_spec_item})
    return specs


class RadwareModuleError(Exception):
    pass


