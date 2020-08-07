###
#
# Lenovo Redfish examples - Get the system log information
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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
import time
import lenovo_utils as utils


def get_system_log(ip, login_account, login_password, system_id, type):
    """Get system log    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params type: The type of log to get
    :type type: string
    :returns: returns system log when succeeded or error message when failed
    """
    result = {}
    log_details = []
    login_host = 'https://' + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    # Get response_base_url resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    if response_base_url.status != 200:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result

    # Find target LogService url from specified resource type
    if type == "system":
        resource_url = response_base_url.dict['Systems']['@odata.id']
    elif type == "manager":
        resource_url = response_base_url.dict['Managers']['@odata.id']
    else:
        resource_url = response_base_url.dict['Chassis']['@odata.id']
    response_resource_url = REDFISH_OBJ.get(resource_url, None)
    if response_resource_url.status != 200:
        result = {'ret': False, 'msg': "response resource url %s failed. Error code %s" % (resource_url, response_resource_url.status)}
        REDFISH_OBJ.logout()
        return result
    resource_count = response_resource_url.dict['Members@odata.count']
    for i in range(resource_count):
        resource_x_url = response_resource_url.dict['Members'][i]['@odata.id']
        response_resource_x_url = REDFISH_OBJ.get(resource_x_url, None)
        if response_resource_x_url.status != 200:
            result = {'ret': False, 'msg': "response resource url %s failed. Error code %s" % (resource_x_url, response_resource_x_url.status)}
            REDFISH_OBJ.logout()
            return result
        if "LogServices" in response_resource_x_url.dict:
            log_services_url = response_resource_x_url.dict['LogServices']['@odata.id']
        else:
            if resource_count > 1:
                continue
            result = {'ret': False, 'msg': "There is no LogServices in %s" % resource_x_url}
            REDFISH_OBJ.logout()
            return result

        # Get log from LogServices
        response_log_services_url = REDFISH_OBJ.get(log_services_url, None)
        if response_log_services_url.status != 200:
            result = {'ret': False, 'msg': "response resource url %s failed. Error code %s" % (log_services_url, response_log_services_url.status)}
            REDFISH_OBJ.logout()
            return result
        members = response_log_services_url.dict['Members']
        for member in members:
            log_url = member['@odata.id']
            # Get the log url resource
            response_log_url = REDFISH_OBJ.get(log_url, None)
            if response_log_url.status != 200:
                result = {'ret': False, 'msg': "response members url Error code %s" % response_log_url.status}
                REDFISH_OBJ.logout()
                return result
            entries_url = response_log_url.dict['Entries']['@odata.id']
            response_entries_url = REDFISH_OBJ.get(entries_url, None)
            if response_entries_url.status != 200:
                result = {'ret': False, 'msg': "response members url Error code %s" % response_entries_url.status}
                REDFISH_OBJ.logout()
                return result
            # description = response_entries_url.dict['Description']
            for logEntry in response_entries_url.dict['Members']:
                entry = {}
                for log_property in ['Id', 'Name', 'Created', 'Message', 'MessageId', 'Severity',
                                               'EntryCode', 'EntryType', 'EventId', 'EventTimestamp', 
                                               'SensorNumber', 'SensorType', 'OemRecordFormat']:
                    if log_property in logEntry:
                        entry[log_property] = logEntry[log_property]

                if entry not in log_details:
                    log_details.append(entry)
                
    result['ret'] = True            
    result['entries'] = log_details
    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def filter_system_log(log_entries, severity, date):
    """filter system log    
    :params log_entries: system log entry list
    :type log_entries: list
    :params severity: specify log severity. "error", "warning", "info" are supported
    :type severity: string
    :params date: filter log within specified date, Support "all", "2hours", "24hours", "7days", "30days"
    :type date: string
    :returns: returns system log entries which can match specified severity and within specified date
    """

    # no need to filter, return all log entries
    if "error" in severity and "warning" in severity and "info" in severity and date == "all":
        return log_entries
        
    filtered_log_entries = list()
    
    # set target severity list
    severity_filter = list()
    if "error" in severity:
        severity_filter.append("Critical")
    if "warning" in severity:
        severity_filter.append("Warning")
    if "info" in severity:
        severity_filter.append("OK")
        
    # convert date into seconds
    date_dict = {
      "2hours"  : 2*60*60,
      "24hours" : 24*60*60,
      "7days"   : 7*24*60*60,
      "30days"  : 30*24*60*60,
    }
    date_filter_second = date_dict.get(date, 0) 
    if date_filter_second == 0:
        date = "all" #default all
    nowtime_second = int(time.time())
    
    # filter by severity list and date
    for log_entry in log_entries:
        if log_entry['Severity'] in severity_filter:
            if date == "all" or check_log_timestamp(log_entry, date_filter_second, nowtime_second):
                filtered_log_entries.append(log_entry)
        else:
            continue

    return filtered_log_entries


def check_log_timestamp(log_entry, date_filter_second, nowtime_second):
    """ check the log_entry's Created timestamp. If timestamp is within date filter, return True, else return False """
    try:
        log_date_time_string = log_entry['Created'].split('.')[0].strip()
        log_second = int(time.mktime(time.strptime(log_date_time_string, "%Y-%m-%dT%H:%M:%S")))
        if (nowtime_second-log_second) > date_filter_second:
            return False
        
    except Exception:
        pass #do not filter if Created format is unknown
            
    return True


import argparse
def add_helpmessage(parser):
    """Add filter system log parameter"""

    parser.add_argument('--type', type=str, default='system', choices=["system", "chassis", "manager"], help='Specify the type of the log to get. Default is system')
    parser.add_argument('--severity', nargs="*", type=str, default='error warning info', help='Specify severity to filter log with severity. "error", "warning", "info" are supported')
    parser.add_argument('--date', type=str, default='all', help='Specify date to filter log within date, Support "all", "2hours", "24hours", "7days", "30days"')

    return parser


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    argget = add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get system log and check result
    result = get_system_log(ip, login_account, login_password, system_id, args.type)
    if result['ret'] is True:
        filtered_entries = filter_system_log(result['entries'], args.severity, args.date)
        sys.stdout.write(json.dumps(filtered_entries, sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
