###
#
# Lenovo Redfish examples - Send test event
#
# Copyright Notice:
#
# Copyright 2019 Lenovo Corporation
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
import datetime

def send_test_event(ip, login_account, login_password,eventid,message,severity):
    """Send test event
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params eventid: event id
        :type eventid: string
        :params message: message of event
        :type message: string
        :params severity: severity of event
        :type severity: string
        :returns: returns Send test event result when succeeded or error message when failed
        """
    #check paramater
    severitylist = ["OK","Warning","Critical"]
    if severity not in severitylist:
        result = {'ret': False,
                  "msg": "Severity scope in [OK,Warning,Critical],please check your input"}
        return result
    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
    try:
        # Get /redfish/v1
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status == 200:
            # Get /redfish/v1/EventService
            event_url = response_base_url.dict["EventService"]["@odata.id"]
            response_event_url = REDFISH_OBJ.get(event_url,None)
            if response_event_url.status == 200:
                # Check EventService Version
                EventService_Version = 130 #default version v1_3_0
                EventService_Type = response_event_url.dict["@odata.type"]
                EventService_Type = EventService_Type.split('.')[-2]
                if EventService_Type.startswith('v'):
                    EventService_Version = int(EventService_Type.replace('v','').replace('_',''))
                # Construct hearders and body to do post
                target_url = response_event_url.dict["Actions"]["#EventService.SubmitTestEvent"]["target"]
                timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+08:00')
                headers = {"Content-Type": "application/json"}
                payload = {}
                if "@Redfish.ActionInfo" in response_event_url.dict["Actions"]["#EventService.SubmitTestEvent"]:
                    actioninfo_url = response_event_url.dict["Actions"]["#EventService.SubmitTestEvent"]["@Redfish.ActionInfo"]
                    response_actioninfo_url = REDFISH_OBJ.get(actioninfo_url, None)
                    if (response_actioninfo_url.status == 200) and ("Parameters" in response_actioninfo_url.dict):
                        for parameter in response_actioninfo_url.dict["Parameters"]:
                            if ("Required" in parameter) and parameter["Required"]:
                               if parameter["Name"] == "EventId":
                                   payload["EventId"] = eventid
                               elif parameter["Name"] == "EventType":
                                   payload["EventType"] = "Alert"
                               elif parameter["Name"] == "EventTimestamp":
                                   payload["EventTimestamp"] = timestamp
                               elif parameter["Name"] == "Message":
                                   payload["Message"] = message
                               elif parameter["Name"] == "MessageArgs":
                                   payload["MessageArgs"] = []
                               elif parameter["Name"] == "MessageId":
                                   payload["MessageId"] = "Created"
                               elif parameter["Name"] == "Severity":
                                   payload["Severity"] = severity
                               elif parameter["Name"] == "OriginOfCondition":
                                   payload["OriginOfCondition"] = event_url
                elif EventService_Version >= 160:
                    payload["EventId"] = eventid
                    payload["EventTimestamp"] = timestamp
                    payload["Message"] = message
                    payload["MessageArgs"] = []
                    payload["MessageId"] = "Created"
                    payload["OriginOfCondition"] = event_url
                elif EventService_Version >= 130:
                    payload["EventId"] = eventid
                    payload["EventTimestamp"] = timestamp
                    payload["Message"] = message
                    payload["MessageArgs"] = []
                    payload["MessageId"] = "Created"
                    payload["Severity"] = severity
                    payload["OriginOfCondition"] = event_url
                elif EventService_Version >= 106:
                    payload["EventId"] = eventid
                    payload["EventType"] = "Alert"
                    payload["EventTimestamp"] = timestamp
                    payload["Message"] = message
                    payload["MessageArgs"] = []
                    payload["MessageId"] = "Created"
                    payload["Severity"] = severity
                    payload["OriginOfCondition"] = event_url
                else:
                    payload["EventId"] = eventid
                    payload["EventType"] = "Alert"
                    payload["EventTimestamp"] = timestamp
                    payload["Message"] = message
                    payload["MessageArgs"] = []
                    payload["MessageId"] = "Created"
                    payload["Severity"] = severity
                response_send_event = REDFISH_OBJ.post(target_url, headers=headers, body=payload)
                if response_send_event.status == 200 or response_send_event.status == 204:
                    result = {"ret":True,"msg":"Send event successsfully,event id is " + eventid \
                              + ",EventType:Alert,EventTimestamp:" + timestamp + ",Message:" + message \
                              + ",MessageArgs:[],MessageId:Created,Severity:" + severity\
                              + ",OriginOfCondition:" + event_url }
                    return result
                else:
                    error_message = utils.get_extended_error(response_send_event)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        target_url, response_send_event.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_event_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    event_url, response_event_url.status, error_message)}
                return result
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "Exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass

def add_helpmessage(argget):
    argget.add_argument('--eventid', type=str,default="40000001",help="The id of the event you want to set")
    argget.add_argument('--message', type=str,default="test event", help="The mssage you want to set")
    argget.add_argument('--severity', type=str, default="OK",
                        help="The severity of the event,supported severity[OK,Warning,Critical]")

def add_parameter():
    """Send test event parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list(example_string='''
Example:
  "python send_test_event.py -i 10.10.10.10 -u USERID -p PASSW0RD --eventid 40000001 --message "This is a test report" --severity OK"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["eventid"] = args.eventid
    parameter_info["message"] = args.message
    parameter_info["severity"] = args.severity
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    eventid = parameter_info["eventid"]
    message = parameter_info["message"]
    severity = parameter_info["severity"]

    # Send test event and check result
    result = send_test_event(ip, login_account,login_password,eventid,message,severity)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + "\n")
    else:
        sys.stderr.write(result['msg'] + '\n')
