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
module: alteon_config_system_time_date
short_description: Manage Time and Date in Radware Alteon
description:
  - Manage Time and Date in Radware Alteon.
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
      - Parameters for Time and Date configuration.
    suboptions:
      date_mm_dd_yyyy:
        description:
          - The date on the real-time clock, in M/D/YYYY format.
          - Note: A zero-length string is displayed if the date is not available.
        required: false
        default: null
        type: str
      time_hh_mm_ss:
        description:
          - The time on the real-time clock, in hh:mm:SS format.
          - Note: A zero-length string is displayed if the time is not available.
        required: false
        default: null
        type: str
      time_zone:
        description:
          - The time zone can be selected by continent-country-area.
        required: false
        default: null
        choices:
        - none
        - africa_Algeria
        - africa_Angola
        - africa_Benin
        - africa_Botswana
        - africa_Burkina_Faso
        - africa_Burundi
        - africa_Cameroon
        - africa_Central_African_Rep
        - africa_Chad
        - africa_Congo_WestDemRepCongo
        - africa_Congo_EastDemRepCongo
        - africa_Congo_Rep
        - africa_Cote_dIvoire
        - africa_Djibouti
        - africa_Egypt
        - africa_Equatorial_Guinea
        - africa_Eritrea
        - africa_Ethiopia
        - africa_Gabon
        - africa_Gambia
        - africa_Ghana
        - africa_Guinea
        - africa_Guinea_Bissau
        - africa_Kenya
        - africa_Lesotho
        - africa_Liberia
        - africa_Libya
        - africa_Malawi
        - africa_Mali_SouthWestMali
        - africa_Mali_NorthEastMali
        - africa_Mauritania
        - africa_Morocco
        - africa_Mozambique
        - africa_Namibia
        - africa_Niger
        - africa_Nigeria
        - africa_Rwanda
        - africa_SaoTome_And_Principe
        - africa_Senegal
        - africa_SierraLeone
        - africa_Somalia
        - africa_SouthAfrica
        - europe_Spain_Mainland
        - africa_Spain_CeutaMelilla
        - atlanticOcean_Spain_CanaryIslands
        - africa_Sudan
        - africa_Swaziland
        - africa_Tanzania
        - africa_Togo
        - africa_Tunisia
        - africa_Uganda
        - africa_Western_Sahara
        - africa_Zambia
        - africa_Zimbabwe
        - americas_Anguilla
        - americas_Antigua_Barbuda
        - americas_Argentina_EArgentina
        - americas_Argentina_MostLocations
        - americas_Argentina_Jujuy
        - americas_Argentina_Catamarca
        - americas_Argentina_Mendoza
        - americas_Aruba
        - americas_Bahamas
        - americas_Barbados
        - americas_Belize
        - americas_Bolivia
        - americas_Brazil_AtlanticIslands
        - americas_Brazil_AmapaEPara
        - americas_Brazil_NEBrazil
        - americas_Brazil_Pernambuco
        - americas_Brazil_Tocantins
        - americas_Brazil_AlagoasSergipe
        - americas_Brazil_SSEBrazil
        - americas_Brazil_MatoGrossoDoSul
        - americas_Brazil_WParaRondonia
        - americas_Brazil_Roraima
        - americas_Brazil_EAmazonas
        - americas_Brazil_WAmazonas
        - americas_Brazil_Acre
        - americas_Canada_NewfoundlandIsland
        - americas_Canada_AtlanTime_NovaScotia
        - americas_Canada_AtlanTime_ELabrador
        - americas_Canada_EastTime_OntarioMostlocation
        - americas_Canada_EastTime_ThunderBay
        - americas_Canada_EastStdTime_PangnirtungNunavut
        - americas_Canada_EastStdTime_EastNunavut
        - americas_Canada_EastStdTime_CenNunavut
        - americas_Canada_CenTime_ManitobaWestOntario
        - americas_Canada_CenTime_RainyRiver
        - americas_Canada_CenTime_WestNunavut
        - americas_Canada_CenStdTime_SaskatchewanMostlocation
        - americas_Canada_CenStdTime_SaskatchewanMidwest
        - americas_Canada_MountTime_AlbertaEastBritishColumbia
        - americas_Canada_MountTime_CentralNorthwestTerritories
        - americas_Canada_MountTime_WestNorthwestTerritories
        - americas_Canada_MountStdTime_DawsonCrkStJohnBritColumbia
        - americas_Canada_PacificTime_WestBritishColumbia
        - americas_Canada_PacificTime_SouthYukon
        - americas_Canada_PacificTime_NorthYukon
        - americas_CaymanIslands
        - americas_Chile_MostLocation
        - americas_Chile_EasterIsland
        - americas_Colombia
        - americas_CostaRica
        - americas_Cuba
        - americas_Dominica
        - americas_DominicanRepublic
        - americas_Ecuador
        - americas_ElSalvado
        - americas_FrenchGuiana
        - americas_Greenland_MostLocation
        - americas_Greenland_EastCoastNorthScoresbysund
        - americas_Greenland_ScoresbysundIttoqqortoormiit
        - americas_Greenland_ThulePituffik
        - americas_Grenada
        - americas_Guadeloupe
        - americas_Guatemala
        - americas_Guyana
        - americas_Haiti
        - americas_Honduras
        - americas_Jamaica
        - americas_Martinique
        - americas_Mexico_CentTime_Mostlocations
        - americas_Mexico_CentTime_QuintanaRoo
        - americas_Mexico_CentTime_CampecheYucatan
        - americas_Mexico_CTime_CoahuilaDurangoNuevoLeonTamaulipas
        - americas_Mexico_MountTime_SBajaNayaritSinaloa
        - americas_Mexico_MountTime_Chihuahua
        - americas_Mexico_MountStdTime_Sonora
        - americas_Mexico_PacificTime
        - americas_Montserrat
        - americas_NetherlandsAntilles
        - americas_Nicaragua
        - americas_Panama
        - americas_Paraguay
        - americas_Peru
        - americas_PuertoRico
        - americas_StKittsAndNevis
        - americas_StLucia
        - americas_StPierreAndMiquelon
        - americas_StVincent
        - americas_Suriname
        - americas_TrinidadAndTobago
        - americas_TurksAndCaicosIs
        - americas_USA_EastTime
        - americas_USA_EastTime_MichiganMostLocation
        - americas_USA_EastTime_KentuckyLouisvilleArea
        - americas_USA_EastTime_KentuckyWayneCounty
        - americas_USA_EastStdTime_IndianaMostLocations
        - americas_USA_EastStdTime_IndianaCrawfordCounty
        - americas_USA_EastStdTime_IndianaStarkeCounty
        - americas_USA_EastStdTime_IndianaSwitzerlandCounty
        - americas_USA_CentTime
        - americas_USA_CentTime_MichiganWisconsinborder
        - americas_USA_CentTime_NorthDakotaOliverCounty
        - americas_USA_MountTime
        - americas_USA_MountTime_SouthIdahoAndEastOregon
        - americas_USA_MountTime_Navajo
        - americas_USA_MountStdTime_Arizona
        - americas_USA_PacificTime
        - americas_USA_AlaskaTime
        - americas_USA_AlaskaTime_AlaskaPanhandle
        - americas_USA_AlaskaTime_AlaskaPanhandleNeck
        - americas_USA_AlaskaTime_WestAlaska
        - americas_USA_AleutianIslands
        - americas_USA_Hawaii
        - americas_Uruguay
        - americas_Venezuela
        - americas_VirginIslands_UK
        - americas_VirginIslands_US
        - antarctica_McMurdoStationRossIsland
        - antarctica_Amundsen_ScottStationSouthPole
        - antarctica_PalmerStationAnversIsland
        - antarctica_MawsonStationHolmeBay
        - antarctica_DavisStationVestfoldHills
        - antarctica_CaseyStationBaileyPeninsula
        - antarctica_VostokStationSMagneticPole
        - antarctica_Dumont_dUrvilleBaseTerreAdelie
        - antarctica_SyowaStationEOngulI
        - arcticOcean_Svalbard
        - arcticOcean_JanMayen
        - asia_Afghanistan
        - asia_Armenia
        - asia_Azerbaijan
        - asia_Bahrain
        - asia_Bangladesh
        - asia_Bhutan
        - asia_Brunei
        - asia_Cambodia
        - asia_China_EastChinaBeijingGuangdongShanghai
        - asia_China_Heilongjiang
        - asia_China_CentralChinaGansuGuizhouSichuanYunnan
        - asia_China_TibetmostofXinjiangUyghur
        - asia_China_SouthwestXinjiangUyghur
        - asia_Cyprus
        - asia_EastTimor
        - asia_Georgia
        - asia_HongKong
        - asia_India
        - asia_Indonesia_JavaAndSumatra
        - asia_Indonesia_WestCentralBorneo
        - asia_Indonesia_EstSthBorneoCelebsBaliNusaTengaraWstTimor
        - asia_Indonesia_IrianJayaAndMoluccas
        - asia_Iran
        - asia_Iraq
        - asia_Israel
        - asia_Japan
        - asia_Jordan
        - asia_Kazakhstan_MostLocations
        - asia_Kazakhstan_QyzylordaKyzylorda
        - asia_Kazakhstan_Aqtobe
        - asia_Kazakhstan_AtyrauMangghystau
        - asia_Kazakhstan_WestKazakhstan
        - asia_Korea_North
        - asia_Korea_South
        - asia_Kuwait
        - asia_Kyrgyzstan
        - asia_Laos
        - asia_Lebanon
        - asia_Macau
        - asia_Malaysia_PeninsularMalaysia
        - asia_Malaysia_SabahSarawak
        - asia_Mongolia_MostLocations
        - asia_Mongolia_BayanOlgiyGoviAltaiHovdUvsZavkhan
        - asia_Mongolia_DornodSukhbaatar
        - asia_Myanmar
        - asia_Nepal
        - asia_Oman
        - asia_Pakistan
        - asia_Palestine
        - asia_Philippines
        - asia_Qatar
        - asia_Russia_Moscow_01Kaliningrad
        - asia_Russia_Moscow00WestRussia
        - asia_Russia_Moscow01CaspianSea
        - asia_Russia_Moscow02Urals
        - asia_Russia_Moscow03WestSiberia
        - asia_Russia_Moscow03Novosibirsk
        - asia_Russia_Moscow04YeniseiRiver
        - asia_Russia_Moscow05LakeBaikal
        - asia_Russia_Moscow06LenaRiver
        - asia_Russia_Moscow07AmurRiver
        - asia_Russia_Moscow07SakhalinIsland
        - asia_Russia_Moscow08Magadan
        - asia_Russia_Moscow09Kamchatka
        - asia_Russia_Moscow10BeringSea
        - asia_SaudiArabia
        - asia_Singapore
        - asia_SriLanka
        - asia_Syria
        - asia_Taiwan
        - asia_Tajikistan
        - asia_Thailand
        - asia_Turkmenistan
        - asia_UnitedArabEmirates
        - asia_Uzbekistan_WestUzbekistan
        - asia_Uzbekistan_EastUzbekistan
        - asia_Vietnam
        - asia_Yemen
        - atlanticOcean_Bermuda
        - atlanticOcean_CapeVerde
        - atlanticOcean_FaeroeIslands
        - atlanticOcean_FalklandIslands
        - atlanticOcean_Iceland
        - atlanticOcean_Portugal_Mainland
        - atlanticOcean_Portugal_MadeiraIslands
        - atlanticOcean_Portugal_Azores
        - atlanticOcean_SouthGeorgia_SouthSandwichIslands
        - atlanticOcean_StHelena
        - atlanticOcean_Svalbard_JanMayen
        - australia_LordHoweIsland
        - australia_Tasmania
        - australia_Victoria
        - australia_NewSouthWales_MostLocations
        - australia_NewSouthWales_Yancowinna
        - australia_Queensland_MostLocations
        - australia_Queensland_HolidayIslands
        - australia_SouthAustralia
        - australia_NorthernTerritory
        - australia_WesternAustralia
        - europe_Albania
        - europe_Andorra
        - europe_Austria
        - europe_Belarus
        - europe_Belgium
        - europe_BosniaHerzegovina
        - europe_Britain_UKGreatBritain
        - europe_Britain_UKNorthernIreland
        - europe_Bulgaria
        - europe_Croatia
        - europe_CzechRepublic
        - europe_Denmark
        - europe_Estonia
        - europe_Finland
        - europe_France
        - europe_Germany
        - europe_Gibraltar
        - europe_Greece
        - europe_Hungary
        - europe_Ireland
        - europe_Italy
        - europe_Latvia
        - europe_Liechtenstein
        - europe_Lithuania
        - europe_Luxembourg
        - europe_Macedonia
        - europe_Malta
        - europe_Moldova
        - europe_Monaco
        - europe_Netherlands
        - europe_Norway
        - europe_Poland
        - europe_Portugal_Mainland
        - europe_Portugal_MadeiraIslands
        - europe_Portugal_Azores
        - europe_Romania
        - europe_Russia_Moscow_01Kaliningrad
        - europe_Russia_Moscow00WestRussia
        - europe_Russia_Moscow01CaspianSea
        - europe_Russia_Moscow02Urals
        - europe_Russia_Moscow03WestSiberia
        - europe_Russia_Moscow03Novosibirsk
        - europe_Russia_Moscow04YeniseiRiver
        - europe_Russia_Moscow05LakeBaikal
        - europe_Russia_Moscow06LenaRiver
        - europe_Russia_Moscow07AmurRiver
        - europe_Russia_Moscow07SakhalinIsland
        - europe_Russia_Moscow08Magadan
        - europe_Russia_Moscow09Kamchatka
        - europe_Russia_Moscow10BeringSea
        - europe_SanMarino
        - europe_Slovakia
        - europe_Slovenia
        - europe_Sweden
        - europe_Switzerland
        - europe_Turkey
        - europe_Ukraine_MostLocations
        - europe_Ukraine_Ruthenia
        - europe_Ukraine_Zaporozhye_ELugansk
        - europe_Ukraine_CentralCrimea
        - europe_VaticanCity
        - europe_Yugoslavia
        - indianOcean_BritishIndianOceanTerritory
        - indianOcean_ChristmasIsland
        - indianOcean_CocosOrKeelingIslands
        - indianOcean_Comoros
        - indianOcean_FrenchSouthernAndAntarcticLands
        - indianOcean_Madagascar
        - indianOcean_Maldives
        - indianOcean_Mauritius
        - indianOcean_Mayotte
        - indianOcean_Reunion
        - indianOcean_Seychelles
        - pacificOcean_Chile_MostLocations
        - pacificOcean_Chile_EasterIslandSalayGomez
        - pacificOcean_CookIslands
        - pacificOcean_Ecuador
        - pacificOcean_Fiji
        - pacificOcean_FrenchPolynesia_SocietyIslands
        - pacificOcean_FrenchPolynesia_MarquesasIslands
        - pacificOcean_FrenchPolynesia_GambierIslands
        - pacificOcean_Guam
        - pacificOcean_Kiribati_GilbertIslands
        - pacificOcean_Kiribati_PhoenixIslands
        - pacificOcean_Kiribati_LineIslands
        - pacificOcean_MarshallIslands_MostLocations
        - pacificOcean_MarshallIslands_Kwajalein
        - pacificOcean_Micronesia_Yap
        - pacificOcean_Micronesia_TrukOrChuuk
        - pacificOcean_Micronesia_PonapeOrPohnpei
        - pacificOcean_Micronesia_Kosrae
        - pacificOcean_Nauru
        - pacificOcean_NewCaledonia
        - pacificOcean_NewZealand_MostLocations
        - pacificOcean_NewZealand_ChathamIslands
        - pacificOcean_Niue
        - pacificOcean_NorfolkIsland
        - pacificOcean_NorthernMarianaIslands
        - pacificOcean_Palau
        - pacificOcean_PapuaNewGuinea
        - pacificOcean_Pitcairn
        - pacificOcean_SamoaAmerican
        - pacificOcean_SamoaWestern
        - pacificOcean_SolomonIslands
        - pacificOcean_Tokelau
        - pacificOcean_Tonga
        - pacificOcean_Tuvalu
        - pacificOceanUSA_EastTime
        - pacificOceanUSA_EastTime_MichiganMostLocations
        - pacificOceanUSA_EastTime_KentuckyLouisvilleArea
        - pacificOceanUSA_EastTime_KentuckyWayneCounty
        - pacificOceanUSA_EastStdTime_IndianaMostLocations
        - pacificOceanUSA_EastStdTime_IndianaCrawfordCounty
        - pacificOceanUSA_EastStdTime_IndianaStarkeCounty
        - pacificOceanUSA_EastStdTime_IndianaSwitzerlandCounty
        - pacificOceanUSA_CentTime
        - pacificOceanUSA_CentTime_MichiganWisconsinborder
        - pacificOceanUSA_CentTime_NorthDakotaOliverCounty
        - pacificOceanUSA_MountTime
        - pacificOceanUSA_MountTime_SouthIdahoAndEastOregon
        - pacificOceanUSA_MountTime_Navajo
        - pacificOceanUSA_MountStdTime_Arizona
        - pacificOceanUSA_PacificTime
        - pacificOceanUSA_AlaskaTime
        - pacificOceanUSA_AlaskaTime_AlaskaPanhandle
        - pacificOceanUSA_AlaskaTime_AlaskaPanhandleNeck
        - pacificOceanUSA_AlaskaTime_WestAlaska
        - pacificOceanUSA_AleutianIslands
        - pacificOceanUSA_Hawaii
        - pacificOcean_USMinorOutlyingIslands_JohnstonAtoll
        - pacificOcean_USMinorOutlyingIslands_MidwayIslands
        - pacificOcean_USMinorOutlyingIslands_WakeIsland
        - pacificOcean_Vanuatu
        - pacificOcean_WallisAndFutuna
      ntp_state:
        description:
          - Specifies whether to enable NTP service.
        required: false
        default: null
        choices:
        - enabled
        - disabled
      ntp_primary_ip4:
        description:
          - The IP address of the primary NTP server.
        required: false
        default: null
        type: str
      ntp_secondary_ip4:
        description:
          - The IP address of the secondary NTP server.
        required: false
        default: null
        type: str
      ntp_primary_ip6:
        description:
          - The IP address of the primary NTP server.
        required: false
        default: null
        type: str
      ntp_secondary_ip6:
        description:
          - The IP address of the secondary NTP server.
        required: false
        default: null
        type: str
      ntp_sync_interval_minute:
        description:
          - The NTP-server-resync interval, in minutes.
        required: false
        default: null
        type: int
      gmt_timezone_offset_hh_mm:
        description:
          - The NTP server timezone offset from GMT formatted as (+/-)HH:MM.
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
  alteon_config_system_time_date:
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
      ntp_state: enabled
      ntp_primary_ip4: 4.6.6.7
      ntp_secondary_ip4: 4.6.6.8
      time_zone: asia_Israel
      ntp_sync_interval_minute: 1400
      gmt_timezone_offset_hh_mm: -02:00
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
from radware.alteon.sdk.configurators.system_time_date import SystemTimeDateConfigurator


class ModuleManager(AlteonConfigurationModule):
    def __init__(self, **kwargs):
        super(ModuleManager, self).__init__(SystemTimeDateConfigurator, **kwargs)


def main():
    spec = ArgumentSpec(SystemTimeDateConfigurator)
    module = AnsibleModule(argument_spec=spec.argument_spec, supports_check_mode=spec.supports_check_mode)

    try:
        mm = ModuleManager(module=module)
        result = mm.exec_module()
        module.exit_json(**result)
    except RadwareModuleError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()

