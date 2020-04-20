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
module: alteon_device_facts
short_description: Collect facts from Alteon device
description:
  - Collect facts from Alteon device
version_added: null
author: 
  - Leon Meguira (@leonmeguira)
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
  gather_subset:
    description:
      - Facts subsets to collects/ignore.
      - A list of facts to include/exclude in output.
      - values starts with C(!)  specify that a specific subset should not be collected.
      - this module execute read command over all alteon configurators and output objects
      - for some configurators *_stats & *_state bean are available 
      - for more details about certain choice , please refer to the approriate module
    required: True
    default: null
    choices:
      - all
      - (!)all
      - system_info
      - (!)system_info
      - system_times
      - (!)system_times
      - system_capacity
      - (!)system_capacity
      - appshape
      - (!)appshape
      - gslb_network
      - (!)gslb_network
      - gslb_rule
      - (!)gslb_rule
      - hc_http
      - (!)hc_http
      - hc_logexp
      - (!)hc_logexp
      - hc_tcp
      - (!)hc_tcp
      - server
      - (!)server
      - server_state
      - (!)server_state
      - server_group
      - (!)server_group
      - ssl_cert
      - (!)ssl_cert
      - ssl_client_auth_policy
      - (!)ssl_client_auth_policy
      - ssl_key
      - (!)ssl_key
      - ssl_policy
      - (!)ssl_policy
      - ssl_server_auth_policy
      - (!)ssl_server_auth_policy
      - vadc_instance
      - (!)vadc_instance
      - vadc_instance_state
      - (!)vadc_instance_state
      - virtual_server
      - (!)virtual_server
      - virtual_service
      - (!)virtual_service
      - virtual_service_state
      - (!)virtual_service_state
      - l2_vlan
      - (!)l2_vlan
      - sys_local_user
      - (!)sys_local_user
      - sys_management_access
      - (!)sys_management_access
      - sys_predefined_local_users
      - (!)sys_predefined_local_users
      - sys_radius_auth
      - (!)sys_radius_auth
      - sys_tacacs_auth
      - (!)sys_tacacs_auth
      - sys_snmp
      - (!)sys_snmp
      - sys_logging
      - (!)sys_logging
      - sys_vx_peer_sync
      - (!)sys_vx_peer_sync
      - sys_alerts
      - (!)sys_alerts
      - sys_dns_client
      - (!)sys_dns_client
      - sys_time_date
      - (!)sys_time_date
      - physical_port
      - (!)physical_port
      - physical_port_state
      - (!)physical_port_state
      - physical_port_stats
      - (!)physical_port_stats
      - lacp_aggregation
      - (!)lacp_aggregation
      - lacp_aggregation_state
      - (!)lacp_aggregation_state
      - spanning_tree
      - (!)spanning_tree
      - l2_lldp
      - (!)l2_lldp
      - l3_interface
      - (!)l3_interface
      - l3_interface_state
      - (!)l3_interface_state
      - l3_gateway
      - (!)l3_gateway
      - l3_gateway_state
      - (!)l3_gateway_state
      - l3_bootp_relay
      - (!)l3_bootp_relay
      - l3_static_routes
      - (!)l3_static_routes
      - ha_floating_ip
      - (!)ha_floating_ip
      - ha_config_sync
      - (!)ha_config_sync
      - high_availability
      - (!)high_availability
      - global_redirection
      - (!)global_redirection
      - global_redirection_state
      - (!)global_redirection_state
      - fdn_server
      - (!)fdn_server
      - network_class_ip
      - (!)network_class_ip
      - network_class_region
      - (!)network_class_region
      - dns_responders
      - (!)dns_responders
notes:
  - Requires Radware alteon Python SDK.
requirements:
  - Radware alteon Python SDK.
'''

EXAMPLES = r'''
- name: alteon device configuration
  alteon_mng_device_configuration:
    provider: 
      server: 192.168.1.1
      user: admin
      password: admin
      validate_certs: no
      https_port: 443
      ssh_port: 22
      timeout: 5
    gather_facts:
      - all
      - gslb_network
      - "!gslb_network"
      - sys_local_user
      - "!spanning_tree"
      - ssl_cert
      - ssl_key
      - "!sys_time_date"
'''

RETURN = r'''
result:
  description: facts parameters object type
  returned: success
  type: dictionary
  sample:
    facts_obj: {
        "global_redirection": [
            {
                "cpu_utilization_threshold_percent": 90,
                "dns_persist_ip4_subnet": "255.255.255.0",
                "dns_persist_ip6_prefix": 64,
                "dns_persist_timeout_minute": 60,
                "dns_persistence_cache_sync": "disabled",
                "dns_redirection_state": "enabled",
                "dssp_tcp_update_port": 80,
                "dssp_version": 1,
                "global_http_redirection": "enabled",
                "global_proxy_redirection": "enabled",
                "hostname_matching": "enabled",
                "no_server_dns_response_code": "not_exist_domain",
                "redirect_to_server_name": "disabled",
                "service_down_response": "srvfail",
                "session_utilization_threshold_percent": 90,
                "site_update_encryption": "enabled",
                "site_update_interval_second": 60,
                "sites": [
                    {
                        "description": "",
                        "ha_peer_device": "disabled",
                        "primary_ip4_address": "8.9.9.9",
                        "primary_ip6_address": null,
                        "primary_ip_ver": "ipv4",
                        "secondary_ip4_address": "0.0.0.0",
                        "secondary_ip6_address": null,
                        "secondary_ip_ver": "ipv4",
                        "site_update_state": "enabled",
                        "state": "enabled"
                    }
                ],
                "state": "on"
            }
        ],
        "system_capacity": {
            "cur_and_ena_appshape_scripts": "3(2)",
            "cur_and_ena_bgp_peers": "0(0)",
            "cur_and_ena_bgp_route_aggrs": "0(0)",
            "cur_and_ena_cache_policies": "1(1)",
            "cur_and_ena_caching_rule_lists": "0(0)",
            "cur_and_ena_caching_rules": "0(0)",
            "cur_and_ena_filters": "0(0)",
            "cur_and_ena_gslb_domains": "1(1)",
            "cur_and_ena_gslb_failovers_per_site": "2(2)",
            "cur_and_ena_gslb_local_servers": "1(1)",
            "cur_and_ena_gslb_metrics_per_rule": "8(8)",
            "cur_and_ena_gslb_networks": "1(1)",
            "cur_and_ena_gslb_regions": "8(8)",
            "cur_and_ena_gslb_remote_servers": "1(1)",
            "cur_and_ena_gslb_rules": "1(2)",
            "cur_and_ena_gslb_services": "2(2)",
            "cur_and_ena_gslb_sites": "1(1)",
            "cur_and_ena_ip_gateways": "0+0(0+0)",
            "cur_and_ena_network_filters": "0(0)",
            "cur_and_ena_ospf_areas": "0(0)",
            "cur_and_ena_ospf_hosts": "0(0)",
            "cur_and_ena_ospf_interfaces": "0(0)",
            "cur_and_ena_ospf_summary_ranges": "0(0)",
            "cur_and_ena_ospf_virtual_links": "0(0)",
            "cur_and_ena_ospfv3_areas": "0(0)",
            "cur_and_ena_ospfv3_hosts": "0(0)",
            "cur_and_ena_ospfv3_interfaces": "0(0)",
            "cur_and_ena_ospfv3_summary_ranges": "0(0)",
            "cur_and_ena_ospfv3_virtual_links": "0(0)",
            "cur_and_ena_port_teams": "8(0)",
            "cur_and_ena_real_servers": "7(7)",
            "cur_and_ena_route_maps": "0(0)",
            "cur_and_ena_security_policies": "0(0)",
            "cur_and_ena_server_groups": 7,
            "cur_and_ena_static_trunks": "0(0)",
            "cur_and_ena_stg_groups": "16(1)",
            "cur_and_ena_virtual_servers": "3(3)",
            "cur_and_ena_vlans": "3(2)",
            "cur_arp_entries": 11,
            "cur_as_filters": "0(0)",
            "cur_bootp_servers": 0,
            "cur_data_class_manual_entries": 0,
            "cur_data_class_mem_size_bytes": 0,
            "cur_data_classes": 0,
            "cur_dns_servers": 0,
            "cur_dynamic_dd_entries": 0,
            "cur_fdb_entries": 0,
            "cur_gslb_dns_persist_cache_entries": "0(10240)",
            "cur_ip_interfaces": "1(1)",
            "cur_ip_route_entries": 5,
            "cur_local_nets": 0,
            "cur_network_classes": 1,
            "cur_network_elements": 1,
            "cur_session_table_entries": 0,
            "cur_smart_nat_entries": 0,
            "cur_ssl_cert_groups": 2,
            "cur_ssl_certs": 2,
            "cur_ssl_csrs": 2,
            "cur_ssl_interm_ca_certs": 0,
            "cur_ssl_keys": 2,
            "cur_ssl_trust_ca_certs": 1,
            "cur_static_arp_entries": 0,
            "cur_static_ip_routes": 0,
            "max_appshape_scripts": 50,
            "max_arp_entries": 8192,
            "max_as_filters": 256,
            "max_bgp_peers": 16,
            "max_bgp_route_aggrs": 16,
            "max_bootp_servers": 2,
            "max_cache_policies": 49,
            "max_caching_rule_lists": 49,
            "max_caching_rules": 500,
            "max_data_class_manual_entries": 16384,
            "max_data_class_mem_size_bytes": 41943040,
            "max_data_classes": 1024,
            "max_dns_servers": 2,
            "max_dynamic_dd_entries": 19032,
            "max_fdb_entries": 16384,
            "max_fdb_per_sp": 8192,
            "max_filters": 2048,
            "max_gslb_dns_persist_cache_entries": 10240,
            "max_gslb_domains": 1024,
            "max_gslb_failovers_per_site": 2,
            "max_gslb_local_servers": 1024,
            "max_gslb_metrics_per_rule": 8,
            "max_gslb_networks": 2048,
            "max_gslb_regions": 8,
            "max_gslb_remote_servers": 2047,
            "max_gslb_rules": 2048,
            "max_gslb_services": 8192,
            "max_gslb_sites": 64,
            "max_ids_groups": 62,
            "max_ip_gateways": "4+255",
            "max_ip_interfaces": 256,
            "max_ip_route_entries": 4096,
            "max_lacp_trunks": 28,
            "max_local_nets": 15,
            "max_manual_entries_per_data_class": 1024,
            "max_monitor_ports": 1,
            "max_network_classes": 1024,
            "max_network_elements": 8192,
            "max_network_filters": 256,
            "max_ospf_areas": 3,
            "max_ospf_hosts": 1024,
            "max_ospf_interfaces": 256,
            "max_ospf_lsdb_limit": 12288,
            "max_ospf_summary_ranges": 16,
            "max_ospf_virtual_links": 3,
            "max_ospfv3_areas": 3,
            "max_ospfv3_hosts": 1024,
            "max_ospfv3_interfaces": 256,
            "max_ospfv3_summary_ranges": 16,
            "max_ospfv3_virtual_links": 3,
            "max_port_teams": 8,
            "max_real_ids_servers": 62,
            "max_real_servers": 2047,
            "max_real_services": 16384,
            "max_route_maps": 32,
            "max_rport_to_vport": 64,
            "max_security_policies": 1023,
            "max_server_groups": 1024,
            "max_session_table_entries": 524275,
            "max_smart_nat_entries": 1024,
            "max_ssl_cert_groups": 128,
            "max_ssl_certs": 99,
            "max_ssl_csrs": 99,
            "max_ssl_interm_ca_certs": 24,
            "max_ssl_keys": 99,
            "max_ssl_trust_ca_certs": 24,
            "max_static_arp_entries": 128,
            "max_static_ip_routes": 1024,
            "max_static_trunks": 12,
            "max_stg_groups": 16,
            "max_trunks_per_trunk_group": 8,
            "max_virtual_servers": 1024,
            "max_virtual_services": 1023,
            "max_vlans": 4096
        },
        "system_info": {
            "device_name": "",
            "eth_board_hw_number": "N/A",
            "eth_board_hw_revision": "N/A",
            "fan_status": "notRelevant",
            "fips_card_status": "notexist",
            "fips_security_level": "none",
            "form_factor": "Standalone",
            "free_memory_mb": 328340,
            "ha_state": "NONE",
            "hard_disk_size_gb": 10,
            "hard_disk_used_gb": 6,
            "mac_address": "00:0c:29:c8:4e:ea",
            "mainboard_hw_number": "N/A",
            "mainboard_hw_revision": "Not Available",
            "management_ipv4_address": "192.168.31.100",
            "management_ipv6_address": "",
            "max_cache_mb": 501,
            "platfrom_id": "VA",
            "power_supply": "notRelevant",
            "serial_number": "N/A",
            "software_version": "31.0.10.50",
            "ssl_chip": "Not Relevant",
            "temperature_sensors": "notRelevant",
            "total_memory_mb": 2566064,
            "total_ram_size_gb": 2,
            "used_cache_mb": 0
        },
        "system_times": {
            "last_apply_time": "00:50:52 Fri Oct 18, 2019",
            "last_boot_time": "16:23:18 Fri Oct 11, 2019 (power cycle)",
            "last_save_time": "21:10:17 Fri Oct  4, 2019",
            "switch_uptime": "11 days, 13 hours, 19 minutes and 59 seconds",
            "system_date": "10/24/2019",
            "system_time": "22:01:07"
        }
    }
'''

from ansible.module_utils.basic import AnsibleModule
import traceback
from typing import get_type_hints
from ansible.module_utils.network.radware.common import RadwareModuleError, radware_server_argument_spec
from ansible.module_utils.network.radware.alteon import AlteonAnsibleModule
from radware.sdk.exceptions import RadwareError
from radware.alteon.api.mgmt import AlteonManagement
from radware.alteon.api.config import AlteonConfigurators
from radware.sdk.configurator import DeviceConfigurator, DeviceConfigurationManager
from radware.alteon.sdk.configurators.ssl_key import SSLKeyConfigurator
from radware.alteon.sdk.configurators.ssl_cert import SSLCertConfigurator
from radware.alteon.sdk.configurators.system_vx_peer_syncronization import VXPeerSyncConfigurator
from radware.alteon.sdk.configurators.vadc_instance import VADCInstanceConfigurator
from radware.alteon.sdk.configurators.spanning_tree import SpanningTreeConfigurator
from radware.alteon.sdk.configurators.l2_lldp import LLDPConfigurator
from radware.alteon.sdk.configurators.system_time_date import SystemTimeDateConfigurator
from radware.alteon.sdk.configurators.lacp_aggregation import LACPAggregationConfigurator
from radware.alteon.sdk.configurators.system_dns_client import SystemDNSClientConfigurator
from radware.alteon.sdk.configurators.l3_bootp_relay import BOOTPRelayConfigurator
from radware.alteon.sdk.configurators.ha_configuration_sync import ConfigurationSyncConfigurator
from radware.alteon.sdk.configurators.high_availability import HighAvailabilityConfigurator
from radware.alteon.sdk.configurators.global_traffic_redirection import GlobalRedirectionConfigurator


STATE_BEANS_VAR_NAME = 'state_beans'
STATS_BEANS_VAR_NAME = 'stats_beans'
MNG_TIME_PROPS = ['last_boot_time',
                  'last_apply_time',
                  'last_save_time',
                  'switch_uptime',
                  'system_time',
                  'system_date']
SYS_INFO_FACTS = 'system_info'
SYS_CAPACITY_FACTS = 'system_capacity'
SYS_TIMES_FACTS = 'system_times'
ADC_SOFTWARE_FACTS = 'adc_software_images'
VX_SOFTWARE_FACTS = 'vx_software_images'


class ArgumentSpecs(object):
    def __init__(self):
        self.supports_check_mode = False
        self.argument_spec = dict(
            gather_facts=dict(
                required=True,
                type='list',
                elements='str',
                choices=self._subset()
            )
        )
        self.argument_spec.update(radware_server_argument_spec)

    def _subset(self):
        subset = list()
        subset.extend(['all', '!all', SYS_INFO_FACTS, self._exclude(SYS_INFO_FACTS), SYS_TIMES_FACTS,
                       self._exclude(SYS_TIMES_FACTS), SYS_CAPACITY_FACTS, self._exclude(SYS_CAPACITY_FACTS),
                       ADC_SOFTWARE_FACTS, self._exclude(ADC_SOFTWARE_FACTS), VX_SOFTWARE_FACTS,
                       self._exclude(VX_SOFTWARE_FACTS)])
        subset.extend(self._mng_subset)
        subset.extend(self._config_subset)
        return subset

    @property
    def _mng_subset(self):
        cfg_subset = list()
        return cfg_subset

    @property
    def _config_subset(self):
        def _add_state_stats(config_class):
            if config_class:
                config_class_meta = get_type_hints(config_class)
                if config_class_meta and STATE_BEANS_VAR_NAME in config_class_meta:
                    cfg_subset.append(self.state(k))
                    cfg_subset.append(self._exclude(self.state(k)))
                if config_class_meta and STATS_BEANS_VAR_NAME in config_class_meta:
                    cfg_subset.append(self.stats(k))
                    cfg_subset.append(self._exclude(self.stats(k)))

        cfg_subset = list()
        meta = get_type_hints(AlteonConfigurators)
        for k, v in meta.items():
            cfg_subset.append(k)
            cfg_subset.append(self._exclude(k))
            _add_state_stats(v)
        return cfg_subset

    @staticmethod
    def _exclude(k):
        return "!{0}".format(k)

    @staticmethod
    def state(k):
        return "{0}_state".format(k)

    @staticmethod
    def stats(k):
        return "{0}_stats".format(k)


class ModuleManager(AlteonAnsibleModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(**kwargs)
        self._facts = self.params['gather_facts']
        self._device_mng = AlteonManagement(self._connection)
        self._configurators = AlteonConfigurators(self._connection)

    def exec_module(self):
        facts_to_collect, exclude_facts = self.filter_excluded_facts()
        result = dict()

        try:
            #self._device_mng.verify_device_accessible(retries=2)
            result.update(self.collect_config_facts(facts_to_collect, exclude_facts))
            result.update(self.collect_mng_facts(facts_to_collect, exclude_facts))
        except RadwareError as e:
            raise RadwareModuleError(e)

        return dict(facts_obj=result)

    def collect_mng_facts(self, facts_list, exclude_list):
        result = dict()
        system_info = dict()
        system_times = dict()

        for k, v in self._device_mng.info.device_sys_info().items():
            if k in MNG_TIME_PROPS:
                system_times.update({k: v})
            else:
                system_info.update({k: v})
        if ('all' in facts_list and SYS_INFO_FACTS not in exclude_list) or SYS_INFO_FACTS in facts_list:
            result.update({SYS_INFO_FACTS: system_info})
        if ('all' in facts_list and SYS_TIMES_FACTS not in exclude_list) or SYS_TIMES_FACTS in facts_list:
            result.update({SYS_TIMES_FACTS: system_times})
        if ('all' in facts_list and SYS_CAPACITY_FACTS not in exclude_list) or SYS_CAPACITY_FACTS in facts_list:
            result.update({SYS_CAPACITY_FACTS: self._device_mng.info.device_sys_capacity()})
        if ('all' in facts_list and ADC_SOFTWARE_FACTS not in exclude_list) or ADC_SOFTWARE_FACTS in facts_list:
            result.update({ADC_SOFTWARE_FACTS: self._device_mng.info.adc_images})
        if ('all' in facts_list and VX_SOFTWARE_FACTS not in exclude_list) or VX_SOFTWARE_FACTS in facts_list:
            result.update({VX_SOFTWARE_FACTS: self._device_mng.info.vx_images})
        return result

    def collect_config_facts(self, facts_list, exclude_list):
        def _translate_filter_bean(beans, bean_filter):
            translated_beans = [b.obj_to_dict() for b in beans]
            if bean_filter and 'exclude' in bean_filter:
                for b in translated_beans:
                    for f_exclude in bean_filter['exclude']:
                        if f_exclude in b:
                            b.pop(f_exclude)
            if bean_filter and 'include' in bean_filter:
                for b in translated_beans:
                    for k in list(b.keys()):
                        if k not in bean_filter['include']:
                            b.pop(k)
            return translated_beans

        def _read_beans(b_classes):
            beans_res = dict()
            if b_classes:
                for bean_class, bean_filter in b_classes.items():
                    beans = self._connection.rest.read_all(bean_class())
                    if beans:
                        beans_res.update({bean_class.__name__: _translate_filter_bean(beans, bean_filter)})
            return beans_res

        def _collect_state_stats():
            state_fact_key = ArgumentSpecs.state(key)
            stats_fact_key = ArgumentSpecs.stats(key)
            if ('all' in facts_list and state_fact_key not in exclude_list) or state_fact_key in facts_list:
                if hasattr(configurator, STATE_BEANS_VAR_NAME):
                    cfg_beans = _read_beans(getattr(configurator, STATE_BEANS_VAR_NAME))
                    result.update({state_fact_key: cfg_beans})
            if ('all' in facts_list and stats_fact_key not in exclude_list) or stats_fact_key in facts_list:
                if hasattr(configurator, STATS_BEANS_VAR_NAME):
                    cfg_beans = _read_beans(getattr(configurator, STATS_BEANS_VAR_NAME))
                    result.update({stats_fact_key: cfg_beans})

        result = dict()
        cfg_mng = DeviceConfigurationManager()
        vx_device = self._device_mng.info.is_vx
        container_device = self._device_mng.info.is_container

        for key in get_type_hints(AlteonConfigurators):
            configurator = getattr(self._configurators, key)
            if ('all' in facts_list and key not in exclude_list) or key in facts_list:
                if type(configurator) == SSLCertConfigurator and not vx_device:
                    result.update({key: cfg_mng.execute(configurator,
                                                        'read_all_cert_info', None).content_translate})
                elif type(configurator) == SSLKeyConfigurator and not vx_device:
                    result.update({key: cfg_mng.execute(configurator,
                                                        'read_all_key_info', None).content_translate})
                elif type(configurator) in [VADCInstanceConfigurator, VXPeerSyncConfigurator] and not vx_device:
                    continue
                elif type(configurator) in [SystemTimeDateConfigurator, SpanningTreeConfigurator, LLDPConfigurator,
                                            LACPAggregationConfigurator] and not container_device:
                    continue
                elif type(configurator) in [SystemDNSClientConfigurator, BOOTPRelayConfigurator,
                                            ConfigurationSyncConfigurator, HighAvailabilityConfigurator,
                                            GlobalRedirectionConfigurator] and vx_device:
                    continue
                else:
                    result.update({key: cfg_mng.execute(configurator,
                                                        DeviceConfigurator.READ_ALL, None).content_translate})
            _collect_state_stats()
        return result

    def filter_excluded_facts(self):
        exclude = [x[1:] for x in self._facts if x[0] == '!']
        include = [x for x in self._facts if x[0] != '!']
        fact_to_collect = [x for x in include if x not in exclude]
        return fact_to_collect, exclude


def main():
    spec = ArgumentSpecs()
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)
    mm = None
    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        if mm:
            mm.module_warn_alteon_version()
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
