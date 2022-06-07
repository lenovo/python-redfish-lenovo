###
#
# Lenovo Redfish examples - Set SNMP global information
#
# Follow below steps to configure SNMP Alert Recipients
# Step 1: Get SNMP engineid from target server as below (Ex. target server ip is 10.245.39.101)
#         #python3 lenovo_generate_snmp_engineid.py -i 10.245.39.101 -u USERID -p PASSW0RD
#         "80 00 1F 88 04 58 43 43 2D 37 58 30 35 2D 4A 33 30 30 43 4B 56 4E"
# Step 2: Setup and configure your SNMP trap receiver (Ex. receiver ip is 10.245.52.18)
#         Ex. Configure your community for SNMPv1 trap as below in net-snmp's /etc/snmp/snmptrapd.conf
#         authCommunity   log,execute,net mypublic
#         Ex. Configure user info for SNMPv3 trap as below in net-snmp's /etc/snmp/snmptrapd.conf
#         createUser -e 0x80001F88045843432D375830352D4A333030434B564E USERID SHA "PASSW0RD" AES "Aa12345678"
#         Ex. Start the trap receiver after configuration as below for snmptrapd
#         #sudo snmptrapd -c /etc/snmp/snmptrapd.conf -Lo -f
# Step 3: Set SNMP global settings to enable SNMPv1/SNMPv3 traps on target server as below
#         #python3 lenovo_set_snmp_global.py -i 10.245.39.101 -u USERID -p PASSW0RD --CriticalEvents all --WarningEvents all --SystemEvents all --snmpv1_community mypublic --snmpv1_trap enable --location mylocation --contact_person myperson --snmpv3_trap enable
# Step 4: Set SNMPv3 user settings on target server as below (skip this for SNMPv1 only)
#         #python3 update_bmc_user_snmpinfo.py -i 10.245.39.101 -u USERID -p PASSW0RD --username USERID --authentication_protocol HMAC_SHA96 --privacy_protocol CFB128_AES128 --privacy_password Aa12345678
# Step 5: Add SNMPv1 or SNMPv3 protocol subscription on target server as below
#         Ex. Add SNMPv1 subscription
#         #python3 add_event_subscriptions.py -i 10.245.39.101 -u USERID -p PASSW0RD --protocol SNMPv1 --destination 10.245.52.18
#         Ex. Add SNMPv3 subscription
#         #python3 add_event_subscriptions.py -i 10.245.39.101 -u USERID -p PASSW0RD --protocol SNMPv3 --destination USERID@10.245.52.18
#
# Copyright Notice:
#
# Copyright 2021 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###



import sys
import json
import redfish
import traceback
import lenovo_utils as utils


def lenovo_set_snmp_global(ip, login_account, login_password, setting_dict):
    """Set snmp global info
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params setting_dict: global setting for all SNMP recipients
    :type setting_dict: string
    :returns: returns snmp global information when succeeded or error message when failed
    """
    result = {}

    # Check parameter
    if setting_dict == {}:
        result = {'ret': False, 'msg': 'No setting option is specified.'}
        return result

    alert_recipient = None
    if 'CriticalEvents' in setting_dict or 'WarningEvents' in setting_dict or 'SystemEvents' in setting_dict:
        alert_recipient = {}
        all_critical_events = ['CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', \
                'CriticalPowerFailure', 'HardDiskDriveFailure', 'FanFailure','CPUFailure', 'MemoryFailure', \
                'HardwareIncompatibility', 'PowerRedundancyFailure', 'AllOtherCriticalEvents']
        all_warning_events = ['PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', \
                'WarningVoltageThresholdExceeded', 'WarningPowerThresholdExceeded', 'NoncriticalFanevents', \
                'CPUinDegradedState', 'MemoryWarning', 'AllOtherWarningEvents']
        all_system_events = ['SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', \
                'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', \
                'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange']

        if 'CriticalEvents' in setting_dict and ('all' in setting_dict['CriticalEvents'] or
                'All' in setting_dict['CriticalEvents']):
            alert_recipient['CriticalEvents'] = {'AcceptedEvents': all_critical_events, 'Enabled': True}
        elif 'CriticalEvents' in setting_dict and ('none' in setting_dict['CriticalEvents'] or
                'None' in setting_dict['CriticalEvents']):
            alert_recipient['CriticalEvents'] = {'AcceptedEvents': [], 'Enabled': False}
        elif 'CriticalEvents' in setting_dict:
            for event in setting_dict['CriticalEvents']:
                if event not in all_critical_events:
                    result = {'ret': False, 'msg': 'Unknown event %s found. Specify "all" or "none" or specify one or more events from AcceptedEvents list: %s' %(event, all_critical_events)}
                    return result
            alert_recipient['CriticalEvents'] = {'AcceptedEvents': setting_dict['CriticalEvents'], 'Enabled': True}

        if 'WarningEvents' in setting_dict and ('all' in setting_dict['WarningEvents'] or
                'All' in setting_dict['WarningEvents']):
            alert_recipient['WarningEvents'] = {'AcceptedEvents': all_warning_events, 'Enabled': True}
        elif 'WarningEvents' in setting_dict and ('none' in setting_dict['WarningEvents'] or
                'None' in setting_dict['WarningEvents']):
            alert_recipient['WarningEvents'] = {'AcceptedEvents': [], 'Enabled': False}
        elif 'WarningEvents' in setting_dict:
            for event in setting_dict['WarningEvents']:
                if event not in all_warning_events:
                    result = {'ret': False, 'msg': 'Unknown event %s found. Specify "all" or "none" or specify one or more events from AcceptedEvents list: %s' %(event, all_warning_events)}
                    return result
            alert_recipient['WarningEvents'] = {'AcceptedEvents': setting_dict['WarningEvents'], 'Enabled': True}

        if 'SystemEvents' in setting_dict and ('all' in setting_dict['SystemEvents'] or
                'All' in setting_dict['SystemEvents']):
            alert_recipient['SystemEvents'] = {'AcceptedEvents': all_system_events, 'Enabled': True}
        elif 'SystemEvents' in setting_dict and ('none' in setting_dict['SystemEvents'] or
                'None' in setting_dict['SystemEvents']):
            alert_recipient['SystemEvents'] = {'AcceptedEvents': [], 'Enabled': False}
        elif 'SystemEvents' in setting_dict:
            for event in setting_dict['SystemEvents']:
                if event not in all_system_events:
                    result = {'ret': False, 'msg': 'Unknown event %s found. Specify "all" or "none" or specify one or more events from AcceptedEvents list: %s' %(event, all_system_events)}
                    return result
            alert_recipient['SystemEvents'] = {'AcceptedEvents': setting_dict['SystemEvents'], 'Enabled': True}

    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object 
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout, 
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE, max_retry=3)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result


    request_url = '/redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/SNMP'

    response_url = REDFISH_OBJ.get(request_url, None)
    if response_url.status == 404:
        result = {'ret': False, 'msg': 'Target server does not support Oem SNMP resource.'}
        REDFISH_OBJ.logout()
        return result

    if response_url.status != 200:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            request_url, response_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    if "@odata.etag" in response_url.dict:
        etag = response_url.dict['@odata.etag']
    else:
        etag = "*"

    if 'snmpv3_agent' in setting_dict and setting_dict['snmpv3_agent'] == 'enable':
        flag_missing = False
        if ('contact_person' in setting_dict and setting_dict['contact_person'] == ''):
            flag_missing = True
        if ('contact_person' not in setting_dict) and (
                response_url.dict['SNMPv3Agent']['ContactPerson'] is None or response_url.dict['SNMPv3Agent']['ContactPerson'] == ''):
            flag_missing = True
        if ('location' in setting_dict and setting_dict['location'] == ''):
            flag_missing = True
        if ('location' not in setting_dict) and (
                response_url.dict['SNMPv3Agent']['Location'] is None or response_url.dict['SNMPv3Agent']['Location'] == ''):
            flag_missing = True
        if flag_missing == True:
            result = {'ret': False, 'msg': 'Input parameter checking failed. Note that snmpv3_agent can only be enabled with contact_person and location being set.'}
            REDFISH_OBJ.logout()
            return result

    if 'snmpv1_trap' in setting_dict and setting_dict['snmpv1_trap'] == 'enable':
        flag_missing = False
        if ('snmpv1_community' in setting_dict and setting_dict['snmpv1_community'] == ''):
            flag_missing = True
        if ('snmpv1_community' not in setting_dict) and (
                len(response_url.dict['CommunityNames']) == 0 or response_url.dict['CommunityNames'][0] == ''):
            flag_missing = True
        if flag_missing == True:
            result = {'ret': False, 'msg': 'Input parameter checking failed. Note that snmpv1_trap can only be enabled with snmpv1_community being set.'}
            REDFISH_OBJ.logout()
            return result

    # Build patch body
    patch_body = {}
    if 'snmpv3_agent' in setting_dict or 'port_agent' in setting_dict or 'contact_person' in setting_dict or 'location' in setting_dict:
        patch_body['SNMPv3Agent'] = {}
        if 'snmpv3_agent' in setting_dict and setting_dict['snmpv3_agent'] == 'enable':
            patch_body['SNMPv3Agent']['ProtocolEnabled'] = True
        elif 'snmpv3_agent' in setting_dict and setting_dict['snmpv3_agent'] != 'enable':
            patch_body['SNMPv3Agent']['ProtocolEnabled'] = False
        if 'port_agent' in setting_dict:
            patch_body['SNMPv3Agent']['Port'] = setting_dict['port_agent']
        if 'contact_person' in setting_dict:
            patch_body['SNMPv3Agent']['ContactPerson'] = setting_dict['contact_person']
        if 'location' in setting_dict:
            patch_body['SNMPv3Agent']['Location'] = setting_dict['location']
    if 'snmpv1_trap' in setting_dict or 'snmpv3_trap' in setting_dict or 'port_trap' in setting_dict:
        patch_body['SNMPTraps'] = {}
        if 'snmpv1_trap' in setting_dict and setting_dict['snmpv1_trap'] == 'enable':
            patch_body['SNMPTraps']['SNMPv1TrapEnabled'] = True
        elif 'snmpv1_trap' in setting_dict and setting_dict['snmpv1_trap'] != 'enable':
            patch_body['SNMPTraps']['SNMPv1TrapEnabled'] = False
        if 'snmpv3_trap' in setting_dict and setting_dict['snmpv3_trap'] == 'enable':
            patch_body['SNMPTraps']['ProtocolEnabled'] = True
        elif 'snmpv3_trap' in setting_dict and setting_dict['snmpv3_trap'] != 'enable':
            patch_body['SNMPTraps']['ProtocolEnabled'] = False
        if 'port_trap' in setting_dict:
            patch_body['SNMPTraps']['Port'] = setting_dict['port_trap']
        if 'snmpv1_address' in setting_dict:
            patch_body['SNMPTraps']['Targets'] = []
            addr = {'Addresses': [setting_dict['snmpv1_address']]}
            patch_body['SNMPTraps']['Targets'].append(addr)
    if 'snmpv1_community' in setting_dict:
        patch_body['CommunityNames'] = [setting_dict['snmpv1_community']]
    if alert_recipient is not None:
        if 'SNMPTraps' not in patch_body:
            patch_body['SNMPTraps'] = {}
        patch_body['SNMPTraps']['AlertRecipient'] = alert_recipient

    # Perform patch
    headers = {"If-Match": etag}
    response_url = REDFISH_OBJ.patch(request_url, body=patch_body, headers=headers)
    if response_url.status in [200,204]:
        result = {'ret': True, 'msg': "The global SNMP info is successfully updated."}
    else:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Update global SNMP info failed, url '%s' response error code %s \nerror_message: %s" % (request_url, response_url.status, error_message)}

    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_helpmessage(parser):
    parser.add_argument('--snmpv3_agent', type=str, required=False, choices=['enable', 'disable'],
            help='Enable or disable SNMPv3 agent. Note that snmpv3_agent can only be enabled with contact_person and location being set.')
    parser.add_argument('--port_agent', type=int, required=False,
            help='Specify the port of SNMPv3 agent.')
    parser.add_argument('--contact_person', type=str, required=False,
            help='Specify the contact person of BMC.')
    parser.add_argument('--location', type=str, required=False,
            help='Specify the location of BMC.')
    parser.add_argument('--snmpv1_trap', type=str, required=False, choices=['enable', 'disable'],
            help='Enable or disable SNMPv1 trap. Note that snmpv1_trap can only be enabled with snmpv1_community being set.')
    parser.add_argument('--snmpv3_trap', type=str, required=False, choices=['enable', 'disable'],
            help='Enable or disable SNMPv3 trap.')
    parser.add_argument('--port_trap', type=int, required=False,
            help='Specify the port of SNMP trap.')
    parser.add_argument('--snmpv1_community', type=str, required=False,
            help='Specify the community of SNMPv1 trap.')
    parser.add_argument('--snmpv1_address', type=str, required=False,
            help='Specify the address of SNMPv1 trap.')

    help_str_critical = "Specify critical events you want to receive."
    help_str_critical += "'all' means all events, 'none' means disable this, or you can specify multiple events, use space to seperate them. example: event1 event2. "
    help_str_critical += "Available events list: "
    help_str_critical += "['CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', 'CriticalPowerFailure', \
                 'HardDiskDriveFailure', 'FanFailure','CPUFailure', 'MemoryFailure', 'HardwareIncompatibility', \
                 'PowerRedundancyFailure', 'AllOtherCriticalEvents']"
    help_str_warning = "Similar with option CriticalEvents, Available events list: "
    help_str_warning += "['PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', 'WarningVoltageThresholdExceeded', \
                 'WarningPowerThresholdExceeded', 'NoncriticalFanevents','CPUinDegradedState', 'MemoryWarning', \
                 'AllOtherWarningEvents']"
    help_str_system = "Similar with option CriticalEvents, Available events list: "
    help_str_system += "['SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', \
                 'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', \
                 'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange']"

    parser.add_argument('--CriticalEvents', type=str, nargs='*', help=help_str_critical)
    parser.add_argument('--WarningEvents', type=str, nargs='*', help=help_str_warning)
    parser.add_argument('--SystemEvents', type=str, nargs='*', help=help_str_system)


def add_parameter():
    """Add parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    setting_dict = {}
    if args.snmpv3_agent is not None:
        setting_dict['snmpv3_agent'] = args.snmpv3_agent
    if args.port_agent is not None:
        setting_dict['port_agent'] = int(args.port_agent)
    if args.contact_person is not None:
        setting_dict['contact_person'] = args.contact_person
    if args.location is not None:
        setting_dict['location'] = args.location
    if args.snmpv1_trap is not None:
        setting_dict['snmpv1_trap'] = args.snmpv1_trap
    if args.snmpv3_trap is not None:
        setting_dict['snmpv3_trap'] = args.snmpv3_trap
    if args.port_trap is not None:
        setting_dict['port_trap'] = int(args.port_trap)
    if args.snmpv1_community is not None:
        setting_dict['snmpv1_community'] = args.snmpv1_community
    if args.snmpv1_address is not None:
        setting_dict['snmpv1_address'] = args.snmpv1_address
    if args.CriticalEvents is not None:
        setting_dict['CriticalEvents'] = args.CriticalEvents
    if args.WarningEvents is not None:
        setting_dict['WarningEvents'] = args.WarningEvents
    if args.SystemEvents is not None:
        setting_dict['SystemEvents'] = args.SystemEvents
    parameter_info['setting_dict'] = setting_dict

    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Set snmp global info and check result
    result = lenovo_set_snmp_global(ip, login_account, login_password, parameter_info['setting_dict'])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

