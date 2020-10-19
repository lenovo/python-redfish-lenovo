###
#
# Lenovo Redfish examples - BMC configuration backup
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
import lenovo_utils as utils
import os
import time

# get file size
def getDocSize(path):
    try:
        size = os.path.getsize(path)
        return size/1024
    except Exception as err:
        sys.stderr.write(err)

def lenovo_bmc_config_backup(ip, login_account, login_password, backup_password, backup_file, httpip, httpport, httpdir):
    """BMC configuration backup
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params backup_password: backup password by user specified
        :type backup_password: string
        :params backup_file: backup file by user specified
        :type backup_file: string
        :params httpip: Specify the file server ip
        :type httpip: string
        :params httpport: Specify the HTTP file server port
        :type httpport: int
        :params httpdir: Specify the file server dir to save
        :type httpdir: string
        :returns: returns BMC configuration backup result when succeeded or error message when failed
        """

    result = {}
    #check passwd len
    if len(backup_password) < 9:
        result = {'ret': False, 'msg': "Password is at least 9 characters"}
        return result

    try:
        back_file = open(backup_file,'w+')
    except:
        result = {'ret': False, 'msg': "Failed to open file %s, Please check your backup file path"%backup_file}
        return result

    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check if the username, password, IP are correct\n"}
        return result
    # Get ServiceBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_base_url
    if response_base_url.status == 200:
        manager_url = response_base_url.dict['Managers']['@odata.id']
    else:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
        '/redfish/v1', response_base_url.status, error_message)}
        REDFISH_OBJ.logout()
        back_file.close()
        return result

    # Get /redfish/v1/Managers resource
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status != 200:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            manager_url, response_manager_url.status, error_message)}
        REDFISH_OBJ.logout()
        back_file.close()
        return result

    for request in response_manager_url.dict['Members']:
        # Get /redfish/v1/Managers/1 resource
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            back_file.close()
            return result

        # Backup from Action #LenovoConfigurationService.BackupConfiguration
        if 'Oem' in response_url.dict and 'Lenovo' in response_url.dict['Oem'] and 'Configuration' in response_url.dict['Oem']['Lenovo']:
            #get configuration url
            oem_resource = response_url.dict['Oem']['Lenovo']
            config_url = oem_resource['Configuration']['@odata.id']
            response_config_url = REDFISH_OBJ.get(config_url, None)
            if response_config_url.status == 200:
                #backup configuration
                backup_target_url = response_config_url.dict['Actions']['#LenovoConfigurationService.BackupConfiguration']['target']
                if "EncryptScope" in str(response_config_url.dict['Actions']):
                    backup_body = {"Passphrase":backup_password, "EncryptScope":"WholeFile"}
                else:
                    backup_body = {"Passphrase":backup_password}
                response_backup_url = REDFISH_OBJ.post(backup_target_url, body=backup_body)
                if response_backup_url.status == 200:
                    json.dump(response_backup_url.dict["data"], back_file, separators=(',',':'))
                    back_file.close()
                    size = getDocSize(backup_file)
                    if(size <= 255):
                        result = {'ret': True,
                                  'msg': "BMC configuration backup successfully, backup file is:" + backup_file}
                    else:
                        os.remove(backup_file)
                        result = {'ret': False,
                                  'msg': "Failed to back up the configuration because the size of configuration data is over 255KB."}
                    REDFISH_OBJ.logout()
                    return result
                else:
                    error_message = utils.get_extended_error(response_backup_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        backup_target_url, response_backup_url.status, error_message)}
                    REDFISH_OBJ.logout()
                    back_file.close()
                    return result
            else:
                error_message = utils.get_extended_error(response_config_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    config_url, response_config_url.status, error_message)}
                REDFISH_OBJ.logout()
                back_file.close()
                return result

        # Backup from Action Oem/Lenovo/Backup.start for SR635/SR655
        elif 'Oem/Lenovo/Backup.start' in str(response_url.dict):
            if httpip is None or httpip == '' or httpdir is None or httpdir == '':
                error_message = "Target Server only support HTTP protocol, please use HTTP file server to backup bmc config."
                result = {"ret": False, "msg": error_message}
                REDFISH_OBJ.logout()
                return result
            body = {}
            body['BackupType'] = 'SNMP, KVM, NetworkAndServices, IPMI, NTP, Authentication, SYSLOG'
            body['password'] = backup_password
            body['serverIP'] = httpip
            body['serverPort'] = httpport
            body['folderPath'] = httpdir
            export_uri = 'http://' + httpip + ':' + str(httpport) + '/' + httpdir
            
            backup_uri = '/redfish/v1/Managers/Self/Actions/Oem/Lenovo/Backup.start'
            time_start=time.time()
            response_backup_uri = REDFISH_OBJ.post(backup_uri, body=body)
            if response_backup_uri.status != 202:
                error_message = utils.get_extended_error(response_backup_uri)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (backup_uri, response_backup_uri.status, error_message)}
                REDFISH_OBJ.logout()
                return result
            task_uri = response_backup_uri.dict['@odata.id']

            # Check task status
            while True:
                response_task_uri = REDFISH_OBJ.get(task_uri, None)
                if response_task_uri.status in [200, 202]:
                    task_state = response_task_uri.dict['TaskState']
                    if task_state == "Completed":
                        time_end = time.time()    
                        print('time cost: %.2f' %(time_end-time_start)+'s')
                        result = {'ret': True, 'msg':  "The backuped bmc config file is saved in %s " %export_uri}
                        break
                    elif task_state in ["Exception", "Killed", "Suspended", "Interrupted", "Cancelled"]:
                        result = {"ret": False, "msg": "Task state is %s, The bmc config backup failed" %task_state}
                        break
                    else:
                        flush()
                else:
                    error_message = utils.get_extended_error(response_task_uri)
                    result = {'ret': False, 'msg': "Url '%s' response task uri Error code %s \nerror_message: %s" % (task_uri, response_task_uri.status, error_message)}
                    break
            
            # Delete the task when the task state is completed
            REDFISH_OBJ.delete(task_uri, None)
            try:
                REDFISH_OBJ.logout()
            except:
                pass
            return result

        else:
            result = {'ret': False, 'msg': "No resource found, not support bmc configuration backup."}
            REDFISH_OBJ.logout()
            return result


def flush():
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + '\r')
        sys.stdout.flush()
        time.sleep(0.1)


def add_helpmessage(parser):
    help_str = "Enter a password that will be used to encrypt data in the file. "
    help_str += "Note that you will be asked for this password when you use the file to restore a configuration."
    help_str += "(Password is at least 9 characters)"
    parser.add_argument('--backuppasswd', type=str, required=True, help= help_str)
    parser.add_argument('--backupfile', type=str,default = "./bmc_config_backup.bak", help='Input the file name you want to save the configuration in local. Note: SR635/SR655 not support local backup, only support backup in http file server')
    parser.add_argument('--httpip', type=str, help='Specify http file server ip for SR635/SR655.')
    parser.add_argument('--httpport', type=int, default=80, help='Specify http file server port for SR635/SR655, default port is 80.')
    parser.add_argument('--httpdir', type=str, help='Specify the directory on http file server for SR635/SR655.')


import configparser
def add_parameter():
    """Add BMC configuration backup parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()

    # Get the configuration file name if the user specified
    config_file = args.config

    # Get the common parameter from the configuration files
    config_ini_info = utils.read_config(config_file)

    # Add FileServerCfg parameter to config_ini_info
    cfg = configparser.ConfigParser()
    if os.path.exists(config_file):
        cfg.read(config_file)
        config_ini_info["httpip"] = cfg.get('FileServerCfg', 'Httpip')
        config_ini_info["httpport"] = cfg.get('FileServerCfg', 'Httpport')
        config_ini_info["httpdir"] = cfg.get('FileServerCfg', 'Httpdir')

    # Get the user specify parameter from the command line
    parameter_info = utils.parse_parameter(args)
    parameter_info["backuppasswd"] = args.backuppasswd
    parameter_info["backupfile"] = args.backupfile
    parameter_info["httpip"] = args.httpip
    parameter_info["httpport"] = args.httpport
    parameter_info["httpdir"] = args.httpdir

    # The parameters in the configuration file are used when the user does not specify parameters
    for key in parameter_info:
        if not parameter_info[key]:
            if key in config_ini_info:
                parameter_info[key] = config_ini_info[key]
    # Use the port specified in configuration file instead of default 80 port
    if config_ini_info["httpport"] != '' and args.httpport == 80:
        parameter_info["httpport"] = int(config_ini_info["httpport"])

    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    backup_password = parameter_info["backuppasswd"]
    backup_file = parameter_info["backupfile"]
    httpip = parameter_info["httpip"]
    httpport = parameter_info["httpport"]
    httpdir = parameter_info["httpdir"]
    #BMC configuration backup and check result
    result = lenovo_bmc_config_backup(ip, login_account, login_password, backup_password, backup_file, httpip, httpport, httpdir)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
