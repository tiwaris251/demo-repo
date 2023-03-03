import re
import config
import pytest
import unittest
import logging
import subprocess
import os
import json
import ib_utils.ib_NIOS as ib_NIOS
import commands
import json, ast
import requests
from time import sleep as sleep
import pexpect
import paramiko
import time
import sys
import socket
from paramiko import client
from ib_utils.start_stop_logs import log_action as log
from ib_utils.file_content_validation import log_validation as logv
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)

host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
class SSH:
    client=None

    def __init__(self,address):
        logging.info ("connecting to server \n : ", address)
        self.client=client.SSHClient()
        self.client.set_missing_host_key_policy(client.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        self.client.connect(address, username='root', pkey = mykey)

    def send_command(self,command):
        if(self.client):
            stdin, stdout, stderr = self.client.exec_command(command)
            result=stdout.read()
            return result


def restart_the_grid():
    logging.info("Restaring the grid")
    grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
    ref = json.loads(grid)[0]['_ref']
    data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
    request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
    sleep(60)
    print("Restrting the grid")


def prod_reboot(ip):
    child = pexpect.spawn('ssh admin@'+ip)
    child.logfile=sys.stdout
    child.expect('password:')
    child.sendline('infoblox')
    child.expect('Infoblox >')
    child.sendline('reboot')
    child.expect('REBOOT THE SYSTEM?')
    child.sendline('y')
    child.expect(pexpect.EOF)
    for i in range(1,20):
        sleep(60)
        status = os.system("ping -c1 -w2 "+ip)
        print(status)
        if status == 0:
            print("System is up")
            break
        else:
            print("System is down")
    sleep(10)
    print("Product Reboot done")

def mem_ref_string(hostname):
    response = ib_NIOS.wapi_request('GET', object_type="member:dns")
    logging.info(response)
    print(response)
    if type(response)!=tuple:
        ref1 = json.loads(response)
        for key in ref1:
            if key.get('host_name') == hostname:
                mem_ref = key.get('_ref')
                break
    else:
        print("Failed to get member DNS ref string")
        mem_ref = "NIL"

    return mem_ref


def mem_ref(hostname):
    response = ib_NIOS.wapi_request('GET', object_type="member")
    logging.info(response)
    print(response)
    if type(response)!=tuple:
        ref1 = json.loads(response)
        for key in ref1:
            if key.get('host_name') == hostname:
                mem_ref = key.get('_ref')
                break
    else:
        print("Failed to get member DNS ref string")
        mem_ref = "NIL"

    return mem_ref

def remove_rpz_rule(rule,zone):
        reference=ib_NIOS.wapi_request('GET', object_type="record:rpz:cname")
        reference=json.loads(reference)
        for i in reference:
            if rule+"."+zone in i["name"]:
                print i["_ref"]
                ref=i["_ref"]
                reference=ib_NIOS.wapi_request('DELETE', object_type=ref)
                print reference
                if type(reference)!=tuple:
                    return reference
                else:
                    return None
                break

def add_rpz_rule(rule,zone):
    data={"name":rule+"."+zone,"rp_zone":zone,"canonical":rule}
    reference3=ib_NIOS.wapi_request('POST', object_type="record:rpz:cname",fields=json.dumps(data))
    if type(reference3)!=tuple:
        return reference3
    else:
        return None



class RFE_V6_interface_cases(unittest.TestCase):
     #############################################  Test cases for RFE_V6_interface  #################################

    @pytest.mark.run(order=1)
    def test_001_enable_ipv6_checks(self):
        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
        logging.info(get_ref)
        res = json.loads(get_ref)
        for i in res:
            ref=i["_ref"]
            data={"use_lan_ipv6_port":True,"use_mgmt_ipv6_port": True,"use_mgmt_port": True}
            response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data))
        logging.info("Test Case Execution Completed")


class RFE_V6_interface_cases(unittest.TestCase):
     #############################################  Test cases for RFE_V6_interface  #################################

    @pytest.mark.run(order=1)
    def test_001_enable_ipv6_checks(self):
        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
        logging.info(get_ref)
        res = json.loads(get_ref)
        for i in res:
            ref=i["_ref"]
            data={"use_lan_ipv6_port":True,"use_mgmt_ipv6_port": True,"use_mgmt_port": True}
            response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data))
        logging.info("Test Case Execution Completed")


class RFE_9980(unittest.TestCase):

#############################################  Test cases Related to Basic Preparation and ZVELO DOWNLOAD #################################


    @pytest.mark.run(order=1)
    def test_001_Start_DNS_Service(self):
        logging.info("Start DNS Service")
        get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
        logging.info(get_ref)
        res = json.loads(get_ref)
        for i in res:
            ref=i["_ref"]
            logging.info("Modify a enable_dns")
            data = {"enable_dns": True}
            response = ib_NIOS.wapi_request('PUT', ref=ref, fields=json.dumps(data))
            sleep(5)
            logging.info(response)
            read  = re.search(r'200',response)
            for read in  response:
                assert True
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=2)
    def test_002_Validate_DNS_service_is_Enabled(self):
        logging.info("Validate DNS Service is enabled")
        get_tacacsplus = ib_NIOS.wapi_request('GET', object_type="member:dns",params="?_return_fields=enable_dns")
        logging.info(get_tacacsplus)
        res = json.loads(get_tacacsplus)
        logging.info(res)
        for i in res:
            if i["enable_dns"] == True:
                logging.info("Test Case Execution Passed")
                assert True
            else:
                logging.info("Test Case Execution Failed")
                assert False



    @pytest.mark.run(order=3)
    def test_003_Configure_Recurson_Forwarer_RPZ_logging_At_Grid_DNS_Properties(self):
        print("\n")
        print("************************************************")
        print("****  Test cases Related to ZVELO DOWNLOAD  ****")
        print("************************************************")
        logging.info("Mofifying and Configure Allow Recursive Query Forwarder and RPZ logging at GRID dns properties")
        get_ref=ib_NIOS.wapi_request('GET', object_type="grid:dns")
        get_ref1=json.loads(get_ref)[0]['_ref']
        logging.info(get_ref1)
        data={"allow_recursive_query":True,"allow_query":[{"_struct": "addressac","address":"Any","permission":"ALLOW"}],"forwarders":[config.forwarder_ip],"logging_categories":{"log_rpz":True,"log_queries":True,"log_responses":True}}
        put_ref=ib_NIOS.wapi_request('PUT', object_type=get_ref1,fields=json.dumps(data))
        logging.info(put_ref)
        if type(put_ref)!=tuple:
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=4)
    def test_004_Validate_Recurson_Forwarer_RPZ_logging_Configured_At_Grid_DNS_Properties(self):
        logging.info("Validating Allow Recursive Query Forwarder and RPZ logging configured at GRID dns properties")
        get_ref=ib_NIOS.wapi_request('GET', object_type="grid:dns?_return_fields=allow_recursive_query,forwarders")
        get_ref1=json.loads(get_ref)
        if get_ref1[0]["allow_recursive_query"]==True and get_ref1[0]["forwarders"]==[config.forwarder_ip]:
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=5)
    def test_005_Configure_DNS_Resolver_At_Grid_Properties(self):
        logging.info("Configure DNs Resolver At GRID properties")
        response = ib_NIOS.wapi_request('GET', object_type="grid")
        response = json.loads(response)
        response=response[0]["_ref"]
        data={"dns_resolver_setting": {"resolvers": [config.resolver_ip]}}
        res = ib_NIOS.wapi_request('PUT', object_type=response,fields=json.dumps(data))
        logging.info(res)
        if type(res)!=tuple:
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=6)
    def test_006_Validate_At_Grid_Properties_DNS_Resolver_Is_Configured_with_loopback_IP(self):
        logging.info("Validating at GRID properties DNS Resolver is configured with Loopback IP")
        response = ib_NIOS.wapi_request('GET', object_type="grid?_return_fields=dns_resolver_setting")
        response = json.loads(response)
        response=response[0]["dns_resolver_setting"]["resolvers"]
        if response==["127.0.0.1",config.resolver_ip]:
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=7)
    def test_007_Enable_Parental_Control_with_Proxy_Settings(self):
        logging.info("Enabling parental control with proxy settings")
        response = ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscriber")
        response = json.loads(response)
        response=response[0]["_ref"]
        logging.info(response)
        data={"enable_parental_control": True,"cat_acctname":"infoblox_sdk", "cat_password":"LinWmRRDX0q","category_url":"https://dl.zvelo.com/","pc_zone_name":"pc.com","cat_update_frequency":1,"proxy_url":config.proxy_server_url,"proxy_username":"proxyclient","proxy_password":"infobox"}
        res = ib_NIOS.wapi_request('PUT', object_type=response,fields=json.dumps(data))
        logging.info(res)
        restart_the_grid()
        sleep(20)
        print res
        if type(res)==tuple:
            if res[0]==400 or res[0]==401:
                logging.info("Test case Execution failed")
                assert False
            else:
                logging.info("Test Case Execution passed")
        else:
            logging.info("Test Case Execution passed")
            assert True

    @pytest.mark.run(order=8)
    def test_008_Validate_Parental_Control_is_Enabled_with_Proxy_Settings(self):
        logging.info("Validating parental control is enabled with Proxy Settings")
        response = ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscriber?_return_fields=enable_parental_control,cat_acctname,category_url,proxy_url")
        logging.info(response)
        response = json.loads(response)
        pc=response[0]["enable_parental_control"]
        act_name=response[0]["cat_acctname"]
        proxy_url=response[0]["proxy_url"]
        if pc==True and act_name=="infoblox_sdk" and proxy_url==config.proxy_server_url:
            logging.info("Test Case execution passed")
            assert True
        else:
            logging.info("Test Case execution Failed")
            assert False


    @pytest.mark.run(order=9)
    def test_009_start_category_download_Messages_logs_on_master(self):
        logging.info("Starting category download Messages Logs on master")
        log("start","/storage/zvelo/log/category_download.log",config.grid_vip)
        logging.info("Test case 116 execution passed")
        time.sleep(2500)



    @pytest.mark.run(order=10)
    def test_010_stop_category_download_Messages_logs_on_master(self):
        logging.info("Stop Syslog Messages Logs on master")
        log("stop","/storage/zvelo/log/category_download.log",config.grid_vip)
        logging.info("Test case execution passed")

    @pytest.mark.run(order=11)
    def test_011_validate_for_zvelo_download_data_completion_on_master(self):
        time.sleep(10)
        logging.info("Validating category download Messages Logs for data completion")
        LookFor="zvelodb download completed"
        logs=logv(LookFor,"/storage/zvelo/log/category_download.log",config.grid_vip)
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution passed")
            assert True
        else:
            logging.info("Test Case Execution failed")
            assert False

    @pytest.mark.run(order=12)
    def test_012_In_Grid_Properties_Configure_Loopback_IP_as_Primary_DNS_Resolver(self):
        logging.info("At GRID properties configure Loopback IP as DNS Resolver")
        response = ib_NIOS.wapi_request('GET', object_type="grid")
        response = json.loads(response)
        response=response[0]["_ref"]
        data={"dns_resolver_setting": {"resolvers": ["127.0.0.1",config.resolver_ip]}}
        res = ib_NIOS.wapi_request('PUT', object_type=response,fields=json.dumps(data))
        logging.info(res)
        if type(res)!=tuple:
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=13)
    def test_013_Validate_At_Grid_Properties_DNS_Resolver_Is_Configured_with_loopback_IP(self):
        logging.info("Validating at GRID properties DNS Resolver is configured with Loopback IP")
        response = ib_NIOS.wapi_request('GET', object_type="grid?_return_fields=dns_resolver_setting")
        response = json.loads(response)
        response=response[0]["dns_resolver_setting"]["resolvers"]
        if response==["127.0.0.1",config.resolver_ip]:
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=14)
    def  test_014_Add_the_Subscriber_Site_as_site2_With_IB_FLEX_Member_DCA_Subscriber_Query_count_and_DCA_Blocklist_White_List_Enabled(self):
        logging.info("Addsubscriber site site2 with IB-FLEX DCA Subscriber Query Count and DCA Blocklist whitelist Enable")
        data={"blocking_ipv4_vip1": "1.1.1.1","blocking_ipv4_vip2": "2.2.2.2","msps":[{"ip_address": config.proxy_server1}],"spms": [{"ip_address": "10.12.11.11"}],"name":"site2","maximum_subscribers":100000,"members":[{"name":config.grid_fqdn}],"nas_gateways":[{"ip_address":config.rad_client_ip,"name":"nas1","shared_secret":"testing123"},{"ip_address":config.rad_client_ip_lan,"name":"nas2","shared_secret":"testing123"}],"dca_sub_query_count":True,"dca_sub_bw_list":True}
        get_ref=ib_NIOS.wapi_request('POST', object_type="parentalcontrol:subscribersite",fields=json.dumps(data))
        logging.info(get_ref)
        print(get_ref)
        restart_the_grid()
        if type(get_ref)!=tuple:
            reference=ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscribersite")
            reference=json.loads(reference)
            if reference[0]["name"]==data["name"]:
                logging.info("Test case execution passed")
                assert True
            else:
                logging.info("Test case execution Failed")
                assert False
        else:
            logging.info(get_ref)
            logging.info("Test case execution Failed")
            assert False


    @pytest.mark.run(order=15)
    def  test_015_Validate_subscriber_site_site2_Is_Added_with_IB_FLEX_Member_DCA_Subscriber_Query_count_and_DCA_Blocklist_White_List_Enabled(self):
        logging.info("Validating subscriber site site2 added with IB-FLEX DCA Subscriber Query Count and DCA Blocklist whitelist Enable")
        reference=ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscribersite?_return_fields=blocking_ipv4_vip1,blocking_ipv4_vip2,dca_sub_query_count,dca_sub_bw_list")
        reference=json.loads(reference)
        if reference[0]["blocking_ipv4_vip1"]=="1.1.1.1" and reference[0]["blocking_ipv4_vip2"]=="2.2.2.2" and reference[0]["dca_sub_query_count"]==True and  reference[0]["dca_sub_bw_list"]==True:
            logging.info("Test case execution passed")
            assert True
        else:
            logging.info("Test case execution failed")
            assert False


    @pytest.mark.run(order=16)
    def test_016_Start_the_subscriber_service_on_members_and_Validate(self):
        logging.info("Start the subscriber service on members and validate")
        member=[config.grid_fqdn]
        for mem in member:
            get_ref=ib_NIOS.wapi_request('GET', object_type='member:parentalcontrol?name='+mem)
            get_ref=json.loads(get_ref)
            ref=get_ref[0]["_ref"]
            print ref
            logging.info(ref)
            data={"enable_service":True}
            reference=ib_NIOS.wapi_request('PUT', object_type=ref,fields=json.dumps(data))
            logging.info(reference)
            print reference
            grid =  ib_NIOS.wapi_request('GET', object_type="grid")
            ref = json.loads(grid)[0]['_ref']
            publish={"member_order":"SIMULTANEOUSLY"}
            request_publish = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=publish_changes",fields=json.dumps(publish))
            time.sleep(1)
            request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=requestrestartservicestatus")
            restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices")
            time.sleep(10)
        for mem in member:
            get_ref=ib_NIOS.wapi_request('GET', object_type='member:parentalcontrol?name='+mem)
            get_ref=json.loads(get_ref)
            if get_ref[0]["enable_service"]==True:
                print("subscriber service is started on "+mem)
                assert True
            else:
                print("Not able to start subscriber service on "+mem)
                assert False
            time.sleep(10)
            logging.info("Test Case Execution Completd")

    @pytest.mark.run(order=17)
    def test_017_start_DCA_service_on_Grid_Master_Member(self):
        logging.info("Enable DCA on the IB-FLEX Grid Master member")
        data = {"enable_dns": True, "enable_dns_cache_acceleration": True}
        DCA_capable=[config.grid_fqdn]
        for mem in DCA_capable:
            grid_ref = mem_ref_string(mem)
            print(grid_ref)
            response = ib_NIOS.wapi_request('PUT', object_type=grid_ref, fields=json.dumps(data))
            print(response)
            if type(response)!=tuple:
                print("DCA Enabled successfully")
                assert True
            else:
                print("Failed to enable DCA on the Member1")
                assert False
        sleep(300)

    @pytest.mark.run(order=18)
    def test_018_Validate_DCA_service_running_on_Grid_Master_Member(self):
        logging.info("Validate_DCA_service_running")
        sys_log_master = 'ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null root@'+str(config.grid_vip)+' " tail -2000 /infoblox/var/infoblox.log"'
        out1 = commands.getoutput(sys_log_master)
        logging.info (out1)
        res1=re.search(r'DNS cache acceleration is now started',out1)
        if res1!=None:
            logging.info("Test Case Execution passed")
            assert True
        else:
            logging.info("Test Case Execution failed")
            assert False

    @pytest.mark.run(order=19)
    def test_019_add_32_rpz_zone(self):
        print("************************************************")
        print("****  Test cases Related to SSP            *****")
        print("************************************************")
        logging.info("Adding 32 RPZ zones")
        for i in range(31,-1,-1):
            data={"fqdn": "rpz"+str(i)+".com","grid_primary":[{"name": config.grid_fqdn,"stealth":False}]}
            reference1=ib_NIOS.wapi_request('POST', object_type="zone_rp",fields=json.dumps(data))
            print(reference1)
            logging.info("adding RPZ zone ")
            data={"name":"pass"+str(i)+".rpz"+str(i)+".com","rp_zone":"rpz"+str(i)+".com","canonical":"pass"+str(i)}
            reference2=ib_NIOS.wapi_request('POST', object_type="record:rpz:cname",fields=json.dumps(data))
            print(reference2)
            data={"name":"nxd"+str(i)+".rpz"+str(i)+".com","rp_zone":"rpz"+str(i)+".com","canonical":""}
            reference3=ib_NIOS.wapi_request('POST', object_type="record:rpz:cname",fields=json.dumps(data))
            print(reference3)
            if type(reference1)!=tuple or type(reference2)!=tuple or type(reference3)!=tuple:
                logging.info("Test case execution passed")
                assert True
            else:
                logging.info("Test case execution failed")
                assert False

            print("Restart DNS Services")
            grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
            ref = json.loads(grid)[0]['_ref']
            data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
            request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
            sleep(30)

    @pytest.mark.run(order=20)
    def test_020_Enable_proxy_rpz_passthru_in_subscriber_site(self):
        logging.info("proxy rpz passthru")
        ref=ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscribersite?_return_fields=proxy_rpz_passthru")
        ref=json.loads(ref)
        ref1=ref[0]["_ref"]
        data={"proxy_rpz_passthru":True}
        ref=ib_NIOS.wapi_request('PUT', object_type=ref1,fields=json.dumps(data))
        print("Restart DNS Services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
        sleep(30)

        if type(ref)!=tuple:
            logging.info("Test case execution passed")
            assert True
        else:
            logging.info("Test case  execution failed")
            assert False

    @pytest.mark.run(order=21)
    def test_021_validate_proxy_rpz_passthru_is_enabled(self):
        logging.info("Disabling proxy rpz passthru")
        ref=ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscribersite?_return_fields=proxy_rpz_passthru")
        ref=json.loads(ref)
        data=ref[0]["proxy_rpz_passthru"]
        if data==True:
            logging.info("Test case  execution passed")
            assert True
        else:
            logging.info("Test case execution failed")
            assert False

    @pytest.mark.run(order=22)
    def test_022_Select_LocalID_in_Subscriber_Services_properties(self):
                logging.info("NAT")
                get_ref = ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscriber")
                logging.info(get_ref)
                res = json.loads(get_ref)
                ref1 = json.loads(get_ref)[0]['_ref']

                logging.info("Modify a enable_PC")

                #data = {"ip_space_discriminator":"Deterministic-NAT-Port"}
                data = {"local_id": "LocalId"}
                response = ib_NIOS.wapi_request('PUT', ref=ref1, fields=json.dumps(data))
                print response
                logging.info(response)
                read  = re.search(r'200',response)
                for read in  response:
                        assert True
                logging.info("Test Case  Execution Completed")


   @pytest.mark.run(order=23)
    def test_023_add_32_rpz_test(self):
        print("************************************************")
        print("****  Test cases Related to SSP            *****")
        print("************************************************")
        logging.info("Adding 32 RPZ tests")
        for i in range(31,-1,-1):
            data={"fqdn": "rpz"+str(i)+".com","grid_primary":[{"name": config.grid_fqdn,"stealth":False}]}
            reference1=ib_NIOS.wapi_request('POST', object_type="test_rp",fields=json.dumps(data))
            print(reference1)
            logging.info("adding RPZ test ")
            data={"name":"pass"+str(i)+".rpz"+str(i)+".com","rp_test":"rpz"+str(i)+".com","canonical":"pass"+str(i)}
            reference2=ib_NIOS.wapi_request('POST', object_type="record:rpz:cname",fields=json.dumps(data))
            print(reference2)
            data={"name":"nxd"+str(i)+".rpz"+str(i)+".com","rp_test":"rpz"+str(i)+".com","canonical":""}
            reference3=ib_NIOS.wapi_request('POST', object_type="record:rpz:cname",fields=json.dumps(data))
            print(reference3)
            if type(reference1)!=tuple or type(reference2)!=tuple or type(reference3)!=tuple:
                logging.info("Test case execution passed")
                assert True
            else:
                logging.info("Test case execution failed")
                assert False

            print("Restart DNS Services")
            grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
            ref = json.loads(grid)[0]['_ref']
            data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
            request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
            sleep(30)

    @pytest.mark.run(order=20)
    def test_024_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=21)
    def test_025_Validate_DCA_Cache_content_shows_Cache_is_empty(self):
        logging.info("Validate_DCA_Cache_content_shows_Cache_is_empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=22)
    def test_026_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_027_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_028_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=25)
    def test_029_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*0.*',c)
        assert re.search(r'.*Cache miss count.*1.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_030_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*cloudfare.com,TYPE65,IN.*AA,TYPE65,cloudfare.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=27)
    def test_031_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_032_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_033_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")



    @pytest.mark.run(order=30)
    def test_034_Validate_as_got_response_from_Cache_hit_count_increased(self):
        logging.info("Validate as got response from Bind for domain cloudfare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*1.*',c)
        assert re.search(r'.*Cache miss count.*1.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)


#response when queried type 65 record for a PCP domain

# order 824 dca


    @pytest.mark.run(order=20)
    def test_035_Copy_Subscriber_Record_radfiles_to_radclient(self):
        logging.info("Copy Subscriber Record radius message files to RAD Client")
        dig_cmd = 'sshpass -p infoblox scp -pr radfiles root@'+str(config.rad_client_ip)+':/root/ '
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'',str(dig_result))
        print "Copied the files to radclient"
        logging.info("Test Case Execution Completed")
        sleep(5)

    @pytest.mark.run(order=21)
    def test_036_From_Radclient_Send_Start_Radius_Message_with_PCP_Policy_and_Proxy_All_Configured(self):
        logging.info("From Rad client send Start Radius message with PCP Policy and Proxy-All Configured")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.rad_client_ip)+' "radclient -q -f radfiles/PCP_1.txt -r 1 '+str(config.grid_vip)+' acct testing123"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(5)

    @pytest.mark.run(order=22)
    def test_037_Validate_Subscriber_Record_with_PCP(self):
        logging.info("Validate Subscriber Record with PCP Policy")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show subscriber_secure_data')
        child.expect('Infoblox >')
        c=child.before
        assert re.search(r'.*'+config.client_ip2+'\/32\|LID\:N\/A\|IPS\:N\/A.*',c)
        logging.info("Test case execution completed")

    @pytest.mark.run(order=23)
    def test_038_From_Radclient_Send_Start_Radius_Message_Different_PCP_Policy_bit_than_above_to_make_sure_Domain_Cache_to_DCA_with_PCP_Word(self):
        logging.info("From Rad client send Start Radius message without Proxy-All set and different PCP Policy bit than the above to make sure Doamin cache_to DCA with PCP word")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.rad_client_ip)+' "radclient -q -f radfiles/PCP_2.txt -r 1 '+str(config.grid_vip)+' acct testing123"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(15)


    @pytest.mark.run(order=24)
    def test_039_Validate_Subscriber_Record_and_Different_PCP_Policy_bit_is_added_to_subscriber_cache(self):
        logging.info("Validate Subscriber Record without Proxy-All set different PCP Policy bit is added to subscriber cache")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show subscriber_secure_data')
        child.expect('Infoblox >')
        c=child.before
        assert re.search(r'.*'+config.client_ip+'\/32\|LID\:N\/A\|IPS\:N\/A.*',c)
        logging.info("Test case execution completed")

    @pytest.mark.run(order=25)
    def test_040_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_041_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip2)+' "dig -t TYPE65 playboy.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*playboy.com.*IN.*HTTPS.*alpn.*ipv4hint.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)


    @pytest.mark.run(order=28)
    def test_042_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=29)
    def test_043_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*playboy.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=25)
    def test_044_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*1.*',c)
        assert re.search(r'.*Cache miss count.*2.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_045_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*playboy.com,TYPE65,IN.*AA,TYPE65,playboy.com.*alpn.*ipv4hint.*ipv6hint.*',c)
        assert re.search(r'.*0x00000000000000000000000000020000.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=25)
    def test_046_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_047_Send_Query_get_response_from_DCA_cache(self):
        logging.info("Perform Query check response as domain playboy.com is in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 playboy.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*playboy.com.*IN.*CNAME.site2-alias-blocking.pc.com.*',str(dig_result))
        assert re.search(r'.*site2-alias-blocking.pc.com.*IN.*CNAME.site2-blocking.pc.com.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)


    @pytest.mark.run(order=28)
    def test_048_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=25)
    def test_049_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*2.*',c)
        assert re.search(r'.*Cache miss count.*2.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

##Client queries without EDNS0

    @pytest.mark.run(order=23)
    def test_050_clear_subscriber_cache(self):
        try:
            logging.info("clear subscriber cache")
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
            child.logfile=sys.stdout
            child.expect('password:',timeout=None)
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set subscriber_secure_data clear_all')
            child.expect('Deleted: 2 records')
            logging.info("Test Case 63 Execution Passed")
            assert True
        except:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=59)
    def test_051_Validate_set_dns_flush_all(self):
        logging.info("Validate set dns flush all")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set dns flush all')
        child.expect('Infoblox >')
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=60)
    def test_052_Validate_dns_cache_empty(self):
        logging.info("Validate dns cache is empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=20)
    def test_053_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=21)
    def test_054_Validate_DCA_Cache_content_shows_Cache_is_empty(self):
        logging.info("Validate_DCA_Cache_content_shows_Cache_is_empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=22)
    def test_055_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as pushclk.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 pushclk.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*pushclk.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_056_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_057_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*pushclk.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=25)
    def test_058_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*2.*',c)
        assert re.search(r'.*Cache miss count.*3.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_059_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*pushclk.com,TYPE65,IN.*AA,TYPE65,pushclk.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=27)
    def test_060_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_061_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 pushclk.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*pushclk.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_062_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")


    @pytest.mark.run(order=30)
    def test_063_Validate_as_got_response_from_Cache_hit_count_increased(self):
        logging.info("Validate as got response from Bind for domain pushclk Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*3.*',c)
        assert re.search(r'.*Cache miss count.*3.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

#if domain cached with edns0,respond from the vDCA cache by stripping out EDNS0

    @pytest.mark.run(order=59)
    def test_064_Validate_set_dns_flush_all(self):
        logging.info("Validate set dns flush all")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set dns flush all')
        child.expect('Infoblox >')
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=60)
    def test_065_Validate_dns_cache_empty(self):
        logging.info("Validate dns cache is empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=20)
    def test_066_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=21)
    def test_067_Validate_DCA_Cache_content_shows_Cache_is_empty(self):
        logging.info("Validate_DCA_Cache_content_shows_Cache_is_empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=22)
    def test_068_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +edns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_069_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_070_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=25)
    def test_071_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*3.*',c)
        assert re.search(r'.*Cache miss count.*4.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_072_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*cloudfare.com,TYPE65,IN.*AA,TYPE65,cloudfare.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        assert re.search(r'.*EDNS0.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=27)
    def test_073_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_074_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_075_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")


    @pytest.mark.run(order=30)
    def test_076_Validate_as_got_response_from_Cache_hit_count_increased(self):
        logging.info("Validate as got response from Bind for domain cloudfare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*4.*',c)
        assert re.search(r'.*Cache miss count.*4.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)



#Client queries with EDNS0



    @pytest.mark.run(order=59)
    def test_077_Validate_set_dns_flush_all(self):
        logging.info("Validate set dns flush all")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set dns flush all')
        child.expect('Infoblox >')
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=60)
    def test_078_Validate_dns_cache_empty(self):
        logging.info("Validate dns cache is empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=20)
    def test_079_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=21)
    def test_080_Validate_DCA_Cache_content_shows_Cache_is_empty(self):
        logging.info("Validate_DCA_Cache_content_shows_Cache_is_empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=22)
    def test_081_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +edns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_082_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_083_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=25)
    def test_084_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*4.*',c)
        assert re.search(r'.*Cache miss count.*5.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_085_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*cloudfare.com,TYPE65,IN.*AA,TYPE65,cloudfare.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        assert re.search(r'.*EDNS0.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=20)
    def test_086_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=22)
    def test_087_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +edns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_088_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_089_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=30)
    def test_090_Validate_as_got_response_from_Cache_hit_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*5.*',c)
        assert re.search(r'.*Cache miss count.*5.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

#If the cached response is without EDNS0 at vDCA - send it to BIND and update the vDCA cache with EDNS0 then respond from cache for the next query


    @pytest.mark.run(order=59)
    def test_091_Validate_set_dns_flush_all(self):
        logging.info("Validate set dns flush all")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set dns flush all')
        child.expect('Infoblox >')
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=60)
    def test_092_Validate_dns_cache_empty(self):
        logging.info("Validate dns cache is empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")


    @pytest.mark.run(order=20)
    def test_093_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=21)
    def test_094_Validate_DCA_Cache_content_shows_Cache_is_empty(self):
        logging.info("Validate_DCA_Cache_content_shows_Cache_is_empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=22)
    def test_095_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_096_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_097_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=25)
    def test_098_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain cloufare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*5.*',c)
        assert re.search(r'.*Cache miss count.*6.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_099_Validate_cloudfare_gets_cached_without_edns(self):
        logging.info("Validate domain  gets cached without edns")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*cloudfare.com,TYPE65,IN.*AA,TYPE65,cloudfare.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=20)
    def test_100_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=22)
    def test_101_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +edns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_102_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_103_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=25)
    def test_104_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*5.*',c)
        assert re.search(r'.*Cache miss count.*7.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_105_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*cloudfare.com,TYPE65,IN.*AA,TYPE65,cloudfare.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        assert re.search(r'.*EDNS0.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=20)
    def test_106_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=22)
    def test_107_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +edns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_108_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_109_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False

    @pytest.mark.run(order=30)
    def test_110_Validate_as_got_response_from_Cache_hit_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*6.*',c)
        assert re.search(r'.*Cache miss count.*7.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

# queries from multiple clients

    @pytest.mark.run(order=59)
    def test_111_Validate_set_dns_flush_all(self):
        logging.info("Validate set dns flush all")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('set dns flush all')
        child.expect('Infoblox >')
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=60)
    def test_112_Validate_dns_cache_empty(self):
        logging.info("Validate dns cache is empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=20)
    def test_113_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)


    @pytest.mark.run(order=21)
    def test_114_Validate_DCA_Cache_content_shows_Cache_is_empty(self):
        logging.info("Validate_DCA_Cache_content_shows_Cache_is_empty")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache is empty.*',c)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=22)
    def test_115_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=23)
    def test_116_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")

    @pytest.mark.run(order=24)
    def test_117_Validate_Named_Log(self):
        logging.info("Validate Named Log when get response from Bind")
        LookFor="named.*info.*cloudfare.*alpn.*ipv4hint.*ech.*ipv6hint.*"
        logs=logv(LookFor,"/var/log/syslog",config.grid_vip)
        logging.info(logs)
        print logs
        if logs!=None:
            logging.info(logs)
            logging.info("Test Case Execution Passed")
            assert True
        else:
            logging.info("Test Case Execution Failed")
            assert False


    @pytest.mark.run(order=25)
    def test_118_Validate_as_got_response_from_Bind__Cache_hit_count_not_increased_and_Miss_cache_count_increased(self):
        logging.info("Validate as got response from Bind for domain clouflare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*6.*',c)
        assert re.search(r'.*Cache miss count.*8.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=26)
    def test_119_Validate_Proxy_Domain_playboy_com_get_cached_to_DCA_When_Send_Query_From_NON_PCP_bit_Matched_and_not_configured_Proxy_All_Subscriber_client(self):
        logging.info("Validate Proxy Domain playboy.com get cached to DCA when send query from the NON PCP bit matched and not configured Proxy-All subscriber client")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel-cache')
        child.expect(':')
        child.sendline('y')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*cloudfare.com,TYPE65,IN.*AA,TYPE65,cloudfare.com.*alpn.*ipv4hint.*ech.*ipv6hint.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)

    @pytest.mark.run(order=27)
    def test_120_start_Syslog_Messages_logs_on_IBFLEX_Member(self):
        logging.info("Starting Syslog Messages Logs on IB-FLEX Member")
        log("start","/var/log/syslog",config.grid_vip)
        logging.info("test case passed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_121_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_122_Send_Query_get_response_from_Bind_As_Not_DCA_Cache(self):
        logging.info("Perform Query from Proxy-All configuredt Subscriber client for Proxy Domain playboy.com using IB-FLEX Member and Validate Proxy IP response from Bind as playboy.com domain is not in DCA cache")
        dig_cmd = 'sshpass -p infoblox ssh -o StrictHostKeyChecking=no -o BatchMode=no  root@'+str(config.client_ip2)+' "dig -t TYPE65 cloudfare.com @'+str(config.grid_vip)+' +nocookie +noedns -b '+config.client_ip2+'"'
        dig_result = subprocess.check_output(dig_cmd, shell=True)
        print dig_result
        assert re.search(r'.*QUERY, status: NOERROR.*',str(dig_result))
        assert re.search(r'.*cloudfare.com.*IN.*HTTPS.*alpn.*ipv4hint.*ech.*ipv6hint.*',str(dig_result))
        logging.info("Test Case Execution Completed")
        sleep(10)

    @pytest.mark.run(order=28)
    def test_123_stop_Syslog_Messages_Logs_on_IB_FLEX_Member(self):
        logging.info("Stopping Syslog Logs on master")
        log("stop","/var/log/syslog",config.grid_vip)
        logging.info("Test Case Execution Completed")



    @pytest.mark.run(order=30)
    def test_124_Validate_as_got_response_from_Cache_hit_count_increased(self):
        logging.info("Validate as got response from Bind for domain cloudfare Cache hit count not increased and Miss cache count increased")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        child.logfile=sys.stdout
        child.expect('password:',timeout=None)
        child.sendline('infoblox')
        child.expect('Infoblox >')
        child.sendline('show dns-accel')
        child.expect('Infoblox >')
        c= child.before
        assert re.search(r'.*Cache hit count.*8.*',c)
        assert re.search(r'.*Cache miss count.*8.*',c)
        logging.info("Test Case Execution Completed")
        sleep(15)
