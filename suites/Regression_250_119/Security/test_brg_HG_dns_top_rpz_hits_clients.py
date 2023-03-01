"""
 Copyright (c) Infoblox Inc., 2016
 Report Name          : DNS Top RPZ Hits 
 Report Category      : DNS Security
 Number of Test cases : 1
 Execution time       : 302.61 seconds
 Execution Group      : Minute Group (MG)
 Description          :

 Author  : Harish
 History : 06/02/2016 (Created)
 Reviewer: Raghavendra MN
"""
import pytest
import unittest
import logging
import subprocess
import json
import os
import ib_utils.ib_validaiton as ib_validation
import ib_utils.ib_system as ib_system
import ib_utils.ib_NIOS as ib_NIOS
import ib_utils.ib_get as ib_get
import config
import pexpect
import sys
import random
import ib_utils.ib_NIOS as ib_NIOS
import ib_utils.ib_get as ib_get
from time import sleep
from logger import logger
from ib_utils.ib_system import search_dump as search_dump
from ib_utils.ib_validaiton import compare_results as compare_results

"""
TEST Steps:
      1.  Input/Preparation  : Add RPZ zones with different types of rules 
                               Perform query opration on added zones to hit the rules with different clients
      2.  Search     : Performing Search operaion with default/custom filter
      3.  Validation : comparing Search results with Reterived 'DNS Top RPZ Hits' report without delta.
"""

class DNSTopRPZHits(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        logger.info('-'*15+"START:DNS Top RPZ Hits"+'-'*15)
        logger.info ("Preparation has executed 1 hour before as this report will take 1 hour to update")
        cls.test1=[]
        temp={}
        temp["Client ID"]=config.client_ip
        temp["Total Client Hits"]="145"
        cls.test1.append(temp)
        logger.info ("Input Json for validation")
        logger.info(json.dumps(cls.test1, sort_keys=True, indent=4, separators=(',', ': ')))


 
          
    def test_1_dns_top_rpz_hits_classes(self):
        logger.info("TestCase:"+sys._getframe().f_code.co_name)
	search_str=r"search index=ib_dns_summary report=si_dns_rpz_hits (orig_host=\"*\")  *  * | stats avg(COUNT) as QCOUNT by _time, VIEW, CLIENT, orig_host | stats sum(QCOUNT) as QCOUNT by _time, CLIENT  | eval QCOUNT=round(QCOUNT)  | convert ctime(_time) as Time   | sort -QCOUNT | head 10  | rename CLIENT as \"Client ID\", QCOUNT as \"Total Client Hits\" | table \"Client ID\", \"Total Client Hits\", Time"
        cmd = config.search_py + " \"" + search_str + "\" --output_mode=json"
        logger.info (cmd) 
        os.system(cmd)
        try:
            retrived_data=open(config.json_file).read()
        except Exception, e:
            logger.error('search operation failed due to %s',e)
            raise Exception("Search operation failed, Please check Grid Configuration")
	output_data = json.loads(retrived_data)
        results_list = output_data['results']
	logger.info("dumping search results in '%s' 'dumps' directory",sys._getframe().f_code.co_name+"_search_output.txt")
        search_dump(sys._getframe().f_code.co_name+"_search_output.txt",self.test1,results_list)
        logger.info("compare_results")
        result = compare_results(self.test1,results_list)
        if result == 0:
            logger.info("Search validation result: %s (PASS)",result)
        else:
            logger.error("Search validation result: %s (FAIL)",result)
        msg = 'Validation is not matching for object which is retrieved from DB %s', result
        assert result == 0, msg 

    @classmethod
    def teardown_class(cls):
       logger.info('-'*15+"END::DNS Top RPZ Hits"+'-'*15)

