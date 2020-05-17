###
#
# Lenovo Redfish examples - Add one alert recipient
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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
import redfish
import json
import lenovo_utils as utils

def lenovo_add_alert_recipient(ip, login_account, login_password, setting_dict):
    """update bmc user global settings 
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params setting_dict: recipient setting
    :type setting_dict: string
    :returns: returns succeeded message or error message when failed
    """
    result = {}
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object 
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, 
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE, max_retry=3)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    try:
        # Get ServiceBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        
        # Get Managers collection resource
        managers_url = response_base_url.dict['Managers']['@odata.id']
        response_managers_url = REDFISH_OBJ.get(managers_url, None)

        # Get Manager resource
        manager_url = response_managers_url.dict['Members'][0]['@odata.id']
        response_manager_url = REDFISH_OBJ.get(manager_url, None)
        
        # Get bmc recipients url
        if 'Oem' in response_manager_url.dict and 'Lenovo' in response_manager_url.dict['Oem'] and 'Recipients' in response_manager_url.dict['Oem']['Lenovo']:
            recipients_url = response_manager_url.dict['Oem']['Lenovo']['Recipients']['@odata.id']
        else:
            result = {'ret': False, 'msg': "No support to add alert recipient."}
            return result
        
        # Get the Id used
        response_recipients_url = REDFISH_OBJ.get(recipients_url, None)
        id_used = []
        for member in response_recipients_url.dict['Members']:
            id_used.append(member['@odata.id'].split("/")[-1])
        
        index_id = setting_dict['Id']
        # if Id is not specified, find first available Id. Otherwise, check the Id specified is being used or not
        if index_id == '':
            for i in range(1, 13):
                if str(i) not in id_used:
                    index_id = str(i)
                    break
            if index_id == '':
                result = {'ret': False, 'msg': "No available Id to add alert recipient."}
                return result
            setting_dict['Id'] = index_id
        else:
            if index_id in id_used:
                result = {'ret': False, 'msg': "Id %s has been used." % index_id}
                return result
        
        # POST setting info body to add one new recipient
        headers = {"Content-Type": "application/json"}
        response_add_recipient = REDFISH_OBJ.post(recipients_url,body=setting_dict, headers=headers)
        if response_add_recipient.status in [200, 201]:
            result = {"ret":True,"msg":"Add alert recipientsuccessfully, id is %s." % setting_dict['Id']}
            return result
        else:
            error_message = utils.get_extended_error(response_add_recipient)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                      recipients_url, response_add_recipient.status, error_message)}
            return result

    except Exception as e:
        result = {'ret':False, 'msg':"Error message %s" % repr(e)}
        return result
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()


import argparse
def add_helpmessage(argget):
    argget.add_argument('--Id', type=int,  required=False, choices=range(1, 13), help='Index id for the recipient, scope is 1 ~ 12. If not specified, first avaliable Id will be used automatically.')
    argget.add_argument('--RecipientName', type=str, required=True, help='Recipient name.')
    argget.add_argument('--IncludeEventLog', type=int, choices=[0, 1], default=1, help='Specify if need to include Event Log contents in the email body, only avaliable for AlertType Email. Default is 1. ')
    argget.add_argument('--Address', type=str, required=True, help='For Syslog, IP:Port, e.g. 10.10.10.10:514. For Email, email address. ')
    argget.add_argument('--Enabledstate', type=int, choices=[0, 1], default=1, help='Specify if enable to send syslog or email. ')
    argget.add_argument('--AlertType', type=str, required=True, choices=['Syslog', 'Email'], help='Specify Syslog or Email.')
    
    
    help_str_critical = "Specify critical events you want to receive."
    help_str_critical += "'all' means all events, or you can specify multiple events, use space to seperate them. example: event1 event2. "
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
                 'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange', 'AllAuditEvents']"
    
    argget.add_argument('--CriticalEvents', type=str, nargs='*', default='', help=help_str_critical)
    argget.add_argument('--WarningEvents', type=str, nargs='*', default='', help=help_str_warning)
    argget.add_argument('--SystemEvents', type=str, nargs='*', default='', help=help_str_system)


def add_parameter():
    # Common parameter handling
    common_str = "This tool can be used to add alert recipient setting. \
                 Example: 'python lenovo_add_alert_recipient.py -i 10.10.10.10 -u USERID -p PASSW0RD \
                 --RecipientName example --Address 10.10.10.10:514 --Enabledstate 1 --AlertType Syslog \
                  --CriticalEvents All --WarningEvents All --SystemEvents SuccessfulRemoteLogin SystemPowerSwitch"
    argget = utils.create_common_parameter_list(description_string=common_str)
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)


    all_critical_events = ['CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', 'CriticalPowerFailure', \
                 'HardDiskDriveFailure', 'FanFailure','CPUFailure', 'MemoryFailure', 'HardwareIncompatibility', \
                 'PowerRedundancyFailure', 'AllOtherCriticalEvents']
    all_warning_events = ['PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', 'WarningVoltageThresholdExceeded', \
                 'WarningPowerThresholdExceeded', 'NoncriticalFanevents','CPUinDegradedState', 'MemoryWarning', 'AllOtherWarningEvents']
    all_system_events = ['SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', \
                 'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', \
                 'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange', 'AllAuditEvents']

    # Create recipient setting based on the arguments specified.
    setting_dict = {}
    setting_dict["RecipientSettings"] = {}
    setting_dict["RecipientSettings"]["EnabledAlerts"] = {}
    setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"] = {}
    setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"] = {}
    setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"] = {}
    
    setting_dict["Id"] = ''
    if args.Id is not None:
        setting_dict["Id"] = str(args.Id)

    setting_dict["RecipientSettings"]["Enabledstate"] = True
    if args.Enabledstate is not None:
        setting_dict["RecipientSettings"]["Enabledstate"] = bool(args.Enabledstate)
    
    if args.RecipientName is not None:
        setting_dict["RecipientSettings"]["RecipientName"] = args.RecipientName
    
    setting_dict["RecipientSettings"]["IncludeEventLog"] = False
    if args.IncludeEventLog is not None and args.AlertType == "Email":
        setting_dict["RecipientSettings"]["IncludeEventLog"] = bool(args.IncludeEventLog)
    
    # Address is key info, all the alerts will be sent to this address. 
    # For Syslog, here is ip:port, like 10.10.10.10:514. 
    # For Email, here is Email address.
    if args.Address is not None:
        setting_dict["RecipientSettings"]["Address"] = args.Address
    
    if args.AlertType is not None:
        setting_dict["RecipientSettings"]["AlertType"] = args.AlertType
    
    setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["Enabled"] = False
    setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["AcceptedEvents"] = []
    if len(args.CriticalEvents) > 0:
        setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["Enabled"] = True
        if 'all' in args.CriticalEvents or 'All' in args.CriticalEvents:
            setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["AcceptedEvents"] = all_critical_events
        else:
            setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["AcceptedEvents"] = args.CriticalEvents
    
    setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["Enabled"] = False
    setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["AcceptedEvents"] = []
    if len(args.WarningEvents) > 0:
        setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["Enabled"] = True
        if 'all' in args.WarningEvents or 'All' in args.WarningEvents:
            setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["AcceptedEvents"] = all_warning_events
        else:
            setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["AcceptedEvents"] = args.WarningEvents

    setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["Enabled"] = False
    setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = []
    if len(args.SystemEvents) > 0:
        setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["Enabled"] = True
        if 'all' in args.SystemEvents or 'All' in args.SystemEvents:
            setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = all_system_events
        else:
            setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = args.SystemEvents
    
    parameter_info["recipient_setting_dict"] = setting_dict
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # check the parameters user specified
    if not parameter_info["recipient_setting_dict"]:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # add one alert recipient   
    result = lenovo_add_alert_recipient(ip, login_account, login_password, parameter_info["recipient_setting_dict"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

