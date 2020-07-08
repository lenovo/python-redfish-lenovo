###
#
# Lenovo Redfish examples - Umount vitual media
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


def lenovo_umount_virtual_media(ip, login_account, login_password, image, mounttype):
    """Unmount virtual media, supporting both 18D and 19A version of Lenovo XCC.
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :param mounttype: Types of mount virtual media.
    :type mounttype:string
    :params image: This value shall specify the eject virtual media image mame
    :type image:string
    :returns: returns eject virtual media iso result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    # Login into the server
    try:
        # Connect using the address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        REDFISH_OBJ.login(auth="basic")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get ServiceRoot resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get response_account_service_url
        if response_base_url.status == 200:
            account_managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': " Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        response_managers_url = REDFISH_OBJ.get(account_managers_url, None)
        if response_managers_url.status == 200:
            # Get manager url form manager resource instance
            count = response_managers_url.dict['Members@odata.count']
            for i in range(count):
                manager_url = response_managers_url.dict['Members'][i]['@odata.id']
                response_manager_url = REDFISH_OBJ.get(manager_url, None)
                if response_manager_url.status == 200:
                    # Get the virtual media url from the manger response
                    virtual_media_url = response_manager_url.dict['VirtualMedia']['@odata.id']
                    # Get mount media iso url
                    remotecontrol_url = ""
                    remotemap_url = ""
                    if "Oem" in response_manager_url.dict:
                        Oem_dict = response_manager_url.dict['Oem']
                        if "Lenovo" in Oem_dict:
                            remotemap_url = Oem_dict['Lenovo']['RemoteMap']['@odata.id']
                            remotecontrol_url = Oem_dict['Lenovo']['RemoteControl']['@odata.id']
                else:
                    error_message = utils.get_extended_error(response_manager_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        manager_url, response_manager_url.status, error_message)}
                    return result

                # Get the mount virtual media list
                response_virtual_media = REDFISH_OBJ.get(virtual_media_url, None)
                if response_virtual_media.status == 200:
                    members_list = response_virtual_media.dict["Members"]
                else:
                    error_message = utils.get_extended_error(response_virtual_media)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        virtual_media_url, response_virtual_media.status, error_message)}
                    return result
                
                # for 19A, XCC predefined 10 members, so call umount function for 19A. otherwise, call function for 18D.
                if len(members_list) == 10:
                    result = umount_virtual_media(REDFISH_OBJ, members_list, image)
                elif len(members_list) <= 4:
                    result = umount_virtual_media_from_cd(REDFISH_OBJ, members_list, image)
                else:
                    if mounttype == "Network":
                        result = umount_all_virtual_from_network(REDFISH_OBJ, remotemap_url)
                    else:
                        result = umount_virtual_media_from_rdoc(REDFISH_OBJ, remotecontrol_url, image)
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            account_managers_url, response_managers_url.status, error_message)}
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout
        REDFISH_OBJ.logout()
        return result


def umount_virtual_media_from_cd(REDFISH_OBJ, members_list, image):
    """
    This function uses the post method to umount virtual media, support AMD server.
    """
    # Get the mount virtual media list
    for members in members_list:
        members_url = members["@odata.id"]
        response_members = REDFISH_OBJ.get(members_url, None)
        if response_members.status == 200:
            image_name = response_members.dict["ImageName"]
            eject_media_url = response_members.dict["Actions"]["#VirtualMedia.EjectMedia"]["target"]
        else:
            error_message = utils.get_extended_error(response_members)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                members_url, response_members.status, error_message)}
            return result
        if image_name == image:
            body = {}
            response = REDFISH_OBJ.post(eject_media_url, body=body)
            if response.status == 204:
                result = {'ret': True, 'msg': "'%s' Umount successfully" % image}
                return result
            else:
                error_message = utils.get_extended_error(response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    eject_media_url, response.status, error_message)}
                return result
        else:
            continue
    result = {"ret": False, "msg": "Please check the image name is correct and has been mounted."}
    return result


def umount_virtual_media(REDFISH_OBJ, members_list, image):
    """
    This function uses the patch method to umount virtual media, support 19A version of XCC.
    """
    # Get the mount virtual media list
    for members in members_list:
        members_url = members["@odata.id"]
        if not members_url.split('/')[-1].startswith("Remote"):
            response_members = REDFISH_OBJ.get(members_url, None)
            if response_members.status == 200:
                image_name = response_members.dict["ImageName"]
            else:
                error_message = utils.get_extended_error(response_members)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    members_url, response_members.status, error_message)}
                return result
            if image_name == image:
                body = {"Image": None}
                response = REDFISH_OBJ.patch(members_url, body=body)
                if response.status == 200:
                    result = {'ret': True, 'msg': "'%s' Umount successfully" % image}
                    return result
                else:
                    error_message = utils.get_extended_error(response)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        members_url, response.status, error_message)}
                    return result
            else:
                continue
    result = {"ret": False, "msg": "Please check the image name is correct and has been mounted."}
    return result


def umount_virtual_media_from_rdoc(REDFISH_OBJ, remotecontrol_url, image):
    """
    This function use the Lenovo OEM extensions to umount virtual media from RDOC, support 18D version of XCC.
    """
    response_remotecontrol_url = REDFISH_OBJ.get(remotecontrol_url, None)
    if response_remotecontrol_url.status == 200:
        mount_image_url = response_remotecontrol_url.dict["MountImages"]["@odata.id"]
    else:
        error_message = utils.get_extended_error(response_remotecontrol_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            remotecontrol_url, response_remotecontrol_url.status, error_message)}
        return result

    # Get all virtual media url from mount image url response
    response_mount_images = REDFISH_OBJ.get(mount_image_url, None)
    if response_mount_images.status == 200:
        image_url_list = response_mount_images.dict["Members"]
    else:
        error_message = utils.get_extended_error(response_mount_images)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            mount_image_url, response_mount_images.status, error_message)}
        return result

    if image == "all":
        for image_url in image_url_list:
            image_url = image_url["@odata.id"]
            if image_url.split("/")[-1].startswith("RDOC"):
                # Umount all virtual media
                delete_image_response = REDFISH_OBJ.delete(image_url, None)
                if delete_image_response.status not in [200, 204]:
                    error_message = utils.get_extended_error(delete_image_response)
                    result = {'ret': False,
                              'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                  image_url, delete_image_response.status, error_message)}
                    return result
                else:
                    continue
        result = {"ret": True, "msg": "Umount all virtual media successfully."}
        return result
    # Umount user specify the virtual media
    else:
        for image_url in image_url_list:
            image_url = image_url["@odata.id"]
            get_image_response = REDFISH_OBJ.get(image_url, None)
            if get_image_response.status == 200:
                mount_iso_name = get_image_response.dict["Name"]
                if image == mount_iso_name:
                    umount_iso_response = REDFISH_OBJ.delete(image_url, None)
                    if umount_iso_response.status in [200, 204]:
                        result = {'ret': True,
                                  'msg': "Virtual media iso (%s) umount successfully" % (image)}
                        return result
                    else:
                        error_message = utils.get_extended_error(umount_iso_response)
                        result = {'ret': False,
                                  'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                      image_url, umount_iso_response.status, error_message)}
                        return result
                else:
                    continue
            else:
                error_message = utils.get_extended_error(get_image_response)
                result = {'ret': False,
                          'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                              image_url, get_image_response.status, error_message)}
                return result
        result = {"ret": False, "msg": "Please check the iso name is correct and has been mounted."}
        return result


def umount_all_virtual_from_network(REDFISH_OBJ, remotemap_url):
    """
    This function use the Lenovo OEM extensions to umount virtual media from Network, support 18D version of XCC.
    """
    response_remotemap_url = REDFISH_OBJ.get(remotemap_url, None)
    if response_remotemap_url.status == 200:
        # Get umount image url form remote map resource instance
        umount_image_url = response_remotemap_url.dict['Actions']['#LenovoRemoteMapService.UMount']['target']
        response_umount_image = REDFISH_OBJ.post(umount_image_url, None)
        if response_umount_image.status in [200, 204]:
            result = {'ret': True, 'msg': "All Media File from Network umount successfully"}
            return result
        else:
            error_message = utils.get_extended_error(response_umount_image)
            result = {'ret': False,
                      'msg': "Umount media iso failed, '%s' response Error code %s \nerror_message: %s" % (
                      remotemap_url, response_umount_image.status, error_message)}
            return result
    else:
        error_message = utils.get_extended_error(response_remotemap_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            remotemap_url, response_remotemap_url.status, error_message)}
        return result


def add_helpmessage(argget):
    argget.add_argument('--mounttype', type=str, default="Network", choices=["Network", "RDOC"],
                        help="Types of mount virtual media.")
    argget.add_argument('--image', type=str, required=True, help='Input the umount virtual media image name')


def add_parameter():
    """Add mount media iso parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['image'] = args.image
    parameter_info['mounttype'] = args.mounttype
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get mount media iso info from the parameters user specified
    try:
        image = parameter_info['image']
        mount_type = parameter_info["mounttype"]
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get mount media iso result and check result
    result = lenovo_umount_virtual_media(ip, login_account, login_password, image, mount_type)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
