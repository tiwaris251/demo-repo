#!/bin/bash

#Set up common test config
. common.config

#Default values
#TEST_CONFIG_FILE=tests.config

function get_timestamp(){
  #secs (since 1970-01-01) + nanaseconds
  TimeStamp=`date '+%s%N'`
  echo $TimeStamp
}

function set_default_config(){

  #TEST_CONFIG_FILE=tests.config
  #Dynamically generate test config file
  echo ""                                              >  ${TEST_CONFIG_FILE}

  #Is this test a Positive/Negative one
  echo "TEST_DESC=\"Positive test\""                   >> ${TEST_CONFIG_FILE}                

  #multiple/single
  echo "TEST_MULTIPLE_OR_SINGLE=single"                >> ${TEST_CONFIG_FILE}  
  #echo "TEST_MULTIPLE_OR_SINGLE=multiple"              >> ${TEST_CONFIG_FILE}  

  #yes/no for with '@' or without '@' in notification in json format           
  echo "TEST_INCLUDE_AT_SIGN=yes"                      >> ${TEST_CONFIG_FILE}                   

  #yes/no for APT or non-APT alert            
  echo "TEST_IS_APT=no"                                >> ${TEST_CONFIG_FILE}                              

  #crit/majr/minr
  #echo "TEST_ALERT_SEVERITY=majr"                      >> ${TEST_CONFIG_FILE} 
  echo "TEST_ALERT_SEVERITY=minr"                      >> ${TEST_CONFIG_FILE} 
  #echo "TEST_ALERT_SEVERITY=crit"                       >> ${TEST_CONFIG_FILE} 
  #echo "TEST_ALERT_SEVERITY=invalid"                       >> ${TEST_CONFIG_FILE} 
  #notified/blocked                   
  echo "TEST_ALERT_ACTION=notified"                    >> ${TEST_CONFIG_FILE}              
  #echo "TEST_ALERT_ACTION=blocked"                      >> ${TEST_CONFIG_FILE}              

}

######################################################################
#  function create_json_file()
######################################################################
function create_json_file(){
  if [ "$1" == "" ]; then
    echo "Input params incomplete!"
  fi

  FILENAME_NOTIFICATION_IN_JSON=$1
  FILENAME_NOTIFICATION_IN_JSON_TEMPLATE="${FILENAME_NOTIFICATION_IN_JSON}.tmpl"

  #Create input json file based on template
  cat ${FILENAME_NOTIFICATION_IN_JSON_TEMPLATE} | sed "s/TEST_ALERT_NAME/${TEST_ALERT_NAME}/g" | sed "s/TEST_FIREEYE_APPLIANCE/${FIREEYE_APPLIANCE}/g" | sed "s/TEST_ALERT_ID/${TEST_ALERT_ID}/g" | sed "s/TEST_ALERT_SEVERITY/${TEST_ALERT_SEVERITY}/g" | sed "s/TEST_ALERT_ACTION/${TEST_ALERT_ACTION}/g" > ${FILENAME_NOTIFICATION_IN_JSON}
  #@ sign support 
  if [ "${TEST_INCLUDE_AT_SIGN}" == "no" ]; then
    #cp ${FILENAME_NOTIFICATION_IN_JSON} ${FILENAME_NOTIFICATION_IN_JSON}.backup
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/\"\@/\"/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
    #cp ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
  #APT alert support
  if [ "${TEST_IS_APT}" == "yes" ]; then
    #cp ${FILENAME_NOTIFICATION_IN_JSON} ${FILENAME_NOTIFICATION_IN_JSON}.backup
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/TEST_APT_NAME/${TEST_APT_NAME}/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
    #cp ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
  if [ "${MALWARE_CALLBACK_DOMAIN}" != "" ]; then
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/MALWARE_CALLBACK_DOMAIN/${MALWARE_CALLBACK_DOMAIN}/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
  if [ "${MALWARE_OBJECT_DOMAIN}" != "" ]; then
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/MALWARE_OBJECT_DOMAIN/${MALWARE_OBJECT_DOMAIN}/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
  if [ "${WEB_INFECTION_DOMAIN}" != "" ]; then
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/WEB_INFECTION_DOMAIN/${WEB_INFECTION_DOMAIN}/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
  if [ "${INFECTION_MATCH_DOMAIN}" != "" ]; then
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/INFECTION_MATCH_DOMAIN/${INFECTION_MATCH_DOMAIN}/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
  if [ "${DOMAIN_MATCH_DOMAIN}" != "" ]; then
    cat ${FILENAME_NOTIFICATION_IN_JSON} | sed "s/DOMAIN_MATCH_DOMAIN/${DOMAIN_MATCH_DOMAIN}/g" > ${FILENAME_NOTIFICATION_IN_JSON}.tmp
    mv ${FILENAME_NOTIFICATION_IN_JSON}.tmp ${FILENAME_NOTIFICATION_IN_JSON}
  fi
}

######################################################################
#  function run_curl_command()
######################################################################
function run_curl_command(){

  CURL=/usr/bin/curl
  if [ ! -f ${CURL} ]; then
    echo "${CURL} not found!"
    exit
  fi
echo "Sending curl command..."
  #${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --request POST --header "Content-Type: application/json" --data-binary @${FILENAME_NOTIFICATION_IN_JSON} ${FIREEYE_ZONE_URL}
  echo "FILENAME_NOTIFICATION_IN_JSON=${FILENAME_NOTIFICATION_IN_JSON}"
  echo "${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --data-binary @${FILENAME_NOTIFICATION_IN_JSON} ${FIREEYE_ZONE_URL}"
  ${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --data-binary @${FILENAME_NOTIFICATION_IN_JSON} ${FIREEYE_ZONE_URL}
  #SQL Injection test:
  #${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:"anything or 'a' = 'a'" --data-binary @${FILENAME_NOTIFICATION_IN_JSON} ${FIREEYE_ZONE_URL}

  echo "...Done"
}

######################################################################
#  function run_testcase_single_alert()
######################################################################
function run_testcase_single_alert(){

  infection_type=""

  if [ "$1" != "" ]; then
    infection_type=$1
    echo "TEST_ALERT_NAME=${infection_type}"             >> ${TEST_CONFIG_FILE} 
  else
    echo "Input params incomplete!"
    return
  fi

  if [ "$2" != "" ]; then
    echo "TEST_ALERT_ID=$2"                              >> ${TEST_CONFIG_FILE}     
  else
    TimeStamp=$(get_timestamp)
    echo "TEST_ALERT_ID=${infection_type}_${TimeStamp}"  >> ${TEST_CONFIG_FILE} 
  fi

  #
  #while getopts ":t:i:" option; do
  #  case "${option}" in
  #    t)
  #      echo "opt: TEST_ALERT_NAME=${option}"
  #      TEST_ALERT_NAME=${option}                        >> ${TEST_CONFIG_FILE}   
  #      ;;
  #    i)
  #	 echo "opt: TEST_ALERT_ID=${option}"
  #      TEST_ALERT_ID=${option}                          >> ${TEST_CONFIG_FILE}   
  #      ;;
  #    *)
  #      echo "no input params provided to run_testcase_single_alert()"
  #      exit
  #      ;;
  #  esac
  #done

  #

  #malware-callback/malware-object/web-infection/infection-match/domain-match


  echo "====Begin of test execution=================================="
  echo "----Begin of test config--------"
  cat ${TEST_CONFIG_FILE}
  echo "----End of test config----------"

  . ${TEST_CONFIG_FILE}

  echo "Executing test for ${TEST_ALERT_NAME} alert with Alert ID: ${TEST_ALERT_ID} ..."

  #JSON file
  if [ "${TEST_IS_APT}" == "yes" ]; then
   FILENAME_APT_SUBSTRING="_apt"
  fi
  FILENAME_NOTIFICATION_IN_JSON="${TEST_ALERT_NAME}${FILENAME_APT_SUBSTRING}_${TEST_MULTIPLE_OR_SINGLE}.json"

  create_json_file ${FILENAME_NOTIFICATION_IN_JSON} #${TEST_ALERT_NAME} ${TEST_IS_APT} ${TEST_MULTIPLE_OR_SINGLE} ${FIREEYE_APPLIANCE} ${TEST_ALERT_ID} ${TEST_ALERT_SEVERITY} ${TEST_ALERT_ACTION} ${TEST_INCLUDE_AT_SIGN}

  run_curl_command #${TEST_ALERT_NAME} ${TEST_IS_APT} ${TEST_MULTIPLE_OR_SINGLE} ${FIREEYE_APPLIANCE} ${TEST_ALERT_ID} ${TEST_ALERT_SEVERITY} ${TEST_ALERT_ACTION} ${TEST_INCLUDE_AT_SIGN}

  echo "Done with test for ${TEST_ALERT_NAME} alert."
  echo "====End of test execution===================================="

}

######################################################################
#  function run_testcase_single_alert_all()
######################################################################
function run_testcase_single_alert_all(){

  #Single alert test
  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
  do
    set_default_config
    run_testcase_single_alert ${infection_type}
  done
}


######################################################################
#  function run_testcase_single_alert_all_invalid_id()
######################################################################
#function run_testcase_single_alert_all_invalid_id(){
#
#  #Single alert test
#  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
#  do
#    set_default_config
#    TEST_ALERT_ID="\\\\\\"   
#    run_testcase_single_alert ${infection_type}  ${TEST_ALERT_ID}
#  done
#}



######################################################################
#  function run_testcase_single_alert_all_invalid_severity()
######################################################################
function run_testcase_single_alert_all_invalid_severity(){

  #Single alert test
  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
  do
    set_default_config
    echo "TEST_ALERT_SEVERITY=invalid"                       >> ${TEST_CONFIG_FILE}    
    run_testcase_single_alert ${infection_type}
  done
}

######################################################################
#  function run_testcase_single_alert_all_without_at_sign()
######################################################################
function run_testcase_single_alert_all_without_at_sign(){

  #Single alert test
  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
  do
    set_default_config
    echo "TEST_INCLUDE_AT_SIGN=no"                       >> ${TEST_CONFIG_FILE}  
    run_testcase_single_alert ${infection_type}
  done
}

######################################################################
#  function run_testcase_single_alert_all_without_at_sign_concurrent()
######################################################################
function run_testcase_single_alert_all_without_at_sign_concurrent(){

  #Single alert test
  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
  do
    set_default_config
    echo "TEST_INCLUDE_AT_SIGN=no"                       >> ${TEST_CONFIG_FILE}  
    run_testcase_single_alert ${infection_type} &
  done
}

######################################################################
#  function run_testcase_single_alert_malware-callback()
######################################################################
function run_testcase_single_alert_malware-callback(){

  #Single alert test
  set_default_config
  if [ "$1" != "" ]; then
    echo "Alert ID is specified!"
    run_testcase_single_alert "malware-callback" "$1"
  else
    run_testcase_single_alert "malware-callback" 
  fi
}


######################################################################
#  function run_testcase_single_alert_malware-object()
######################################################################
function run_testcase_single_alert_malware-object(){

  #Single alert test
  set_default_config
  
  if [ "$1" != "" ]; then
    echo "Alert ID is specified!"
    run_testcase_single_alert "malware-object" "$1"
  else
    run_testcase_single_alert "malware-object"
  fi
}

######################################################################
#  function run_testcase_single_alert_web-infection()
######################################################################
function run_testcase_single_alert_web-infection(){


  #Single alert test
  set_default_config

  if [ "$1" != "" ]; then
    echo "Alert ID is specified!"
    run_testcase_single_alert "web-infection" "$1"
  else
    run_testcase_single_alert "web-infection"
  fi

}


######################################################################
#  function run_testcase_single_alert_infection-match()
######################################################################
function run_testcase_single_alert_infection-match(){

  #Single alert test
  set_default_config

  if [ "$1" != "" ]; then
    echo "Alert ID is specified!"
    run_testcase_single_alert "infection-match" "$1"
  else
    run_testcase_single_alert "infection-match"
  fi

}

######################################################################
#  function run_testcase_single_alert_domain-match()
######################################################################
function run_testcase_single_alert_domain-match(){

  #Single alert test
  set_default_config
  run_testcase_single_alert "domain-match"

  if [ "$1" != "" ]; then
    echo "Alert ID is specified!"
    run_testcase_single_alert "domain-match" "$1"
  else
    run_testcase_single_alert "domain-match"
  fi

}

######################################################################
#  function run_testcase_multiple_alerts_malware-callback()
######################################################################
function run_testcase_multiple_alerts_malware-callback(){

  set_default_config
  echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}
  run_testcase_single_alert "malware-callback"
}


######################################################################
#  function run_testcase_multiple_alerts_malware-object()
######################################################################
function run_testcase_multiple_alerts_malware-object(){

  set_default_config
  echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}

  run_testcase_single_alert "malware-object"
}


######################################################################
#  function run_testcase_multiple_alerts_web-infection()
######################################################################
function run_testcase_multiple_alerts_web-infection(){

  set_default_config
  echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}
  run_testcase_single_alert "web-infection"
}


######################################################################
#  function run_testcase_multiple_alerts_infection-match()
######################################################################
function run_testcase_multiple_alerts_infection-match(){

  set_default_config
  echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}
  run_testcase_single_alert "infection-match"
}

######################################################################
#  function run_testcase_multiple_alerts_domain-match()
######################################################################
function run_testcase_multiple_alerts_domain-match(){

  set_default_config
  echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}
  run_testcase_single_alert "domain-match"
}

######################################################################
#  function run_testcase_multiple_alerts_all()
######################################################################
function run_testcase_multiple_alerts_all(){

  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
  do
    set_default_config
    echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert ${infection_type} 
  done
}

######################################################################
#  function run_testcase_multiple_alerts_all_concurrent()
######################################################################
function run_testcase_multiple_alerts_all_concurrent(){

  for infection_type in `echo "${FIREEYE_INFECTION_TYPES}"`
  do
    set_default_config
    echo "TEST_MULTIPLE_OR_SINGLE=multiple"                >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert ${infection_type}  &
    #run_testcase_single_alert ${infection_type}  
  done
}

######################################################################
#  function run_testcase_multiple_alerts_all_concurrent_multipletimes()
######################################################################
function run_testcase_multiple_alerts_all_concurrent_multipletimes(){

for i in {1..10};
do
  run_testcase_multiple_alerts_all_concurrent 
done

}

######################################################################
#  function run_testcase_multiple_alerts_all_multipletimes()
######################################################################
function run_testcase_multiple_alerts_all_multipletimes(){

for i in {1..10};
do
  run_testcase_multiple_alerts_all 
done

}

######################################################################
#  function run_testcase_single_alert_malware-callback_apt()
######################################################################
function run_testcase_single_alert_malware-callback_apt(){

  if [ "$1" == "" ]; then
    echo "APT name is missing!"
    return
  fi

  run_testcase_single_alert_apt_generic "malware-callback" "$1"

}

######################################################################
#  function run_testcase_single_alert_malware-object_apt()
######################################################################
function run_testcase_single_alert_malware-object_apt(){

  if [ "$1" == "" ]; then
    echo "APT name is missing!"
    return
  fi

  run_testcase_single_alert_apt_generic "malware-object" "$1"

}

######################################################################
#  function run_testcase_single_alert_web-infection_apt()
######################################################################
function run_testcase_single_alert_web-infection_apt(){

  if [ "$1" == "" ]; then
    echo "APT name is missing!"
    return
  fi

  run_testcase_single_alert_apt_generic "web-infection" "$1"

}

######################################################################
#  function run_testcase_single_alert_infection-match_apt()
######################################################################
function run_testcase_single_alert_infection-match_apt(){

  if [ "$1" == "" ]; then
    echo "APT name is missing!"
    return
  fi

  run_testcase_single_alert_apt_generic "infection-match" "$1"

}

######################################################################
#  function run_testcase_single_alert_domain-match_apt()
######################################################################
function run_testcase_single_alert_domain-match_apt(){

  if [ "$1" == "" ]; then
    echo "APT name is missing!"
    return
  fi

  run_testcase_single_alert_apt_generic "domain-match" "$1"

  return

    #"XXX.APT.XXX"
    set_default_config
    #yes/no for APT or non-APT alert            
    echo "TEST_IS_APT=yes"                                >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=Trojan.APT.DNS"                   >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

    #"APT.XXX"
    set_default_config
    #yes/no for APT or non-APT alert            
    echo "TEST_IS_APT=yes"                                >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=APT.DNS"                          >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

    #"XXX.APT"
    set_default_config
    #yes/no for APT or non-APT alert            
    echo "TEST_IS_APT=yes"                                >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=Trojan.APT"                       >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

    #"APT" -- Non-APT alert
    set_default_config
    #yes/no for APT or non-APT alert            
    #Is this test a Positive/Negative one
    echo "TEST_DESC=\"Negative test\""                   >> ${TEST_CONFIG_FILE}
    echo "TEST_IS_APT=yes"                               >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=APT"                             >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

    #"APT " -- Non-APT alert
    set_default_config
    #yes/no for APT or non-APT alert            
    #Is this test a Positive/Negative one
    echo "TEST_DESC=\"Negative test\""                   >> ${TEST_CONFIG_FILE}
    echo "TEST_IS_APT=yes"                               >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=APT "                            >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

    #".APT" -- Non-APT alert
    set_default_config
    #yes/no for APT or non-APT alert            
    #Is this test a Positive/Negative one
    echo "TEST_DESC=\"Negative test\""                   >> ${TEST_CONFIG_FILE}
    echo "TEST_IS_APT=yes"                               >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=.APT"                            >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

    #"APT." -- Non-APT alert
    set_default_config
    #yes/no for APT or non-APT alert            
    #Is this test a Positive/Negative one
    echo "TEST_DESC=\"Negative test\""                   >> ${TEST_CONFIG_FILE}
    echo "TEST_IS_APT=yes"                               >> ${TEST_CONFIG_FILE}
    echo "TEST_APT_NAME=APT."                            >> ${TEST_CONFIG_FILE}
    run_testcase_single_alert "domain-match"

}

######################################################################
#  function run_testcase_single_alert_apt_generic()
######################################################################
function run_testcase_single_alert_apt_generic(){
  if [ "$1" == "" ]; then
    echo "alert type is missing!"
    return
  fi

  if [ "$2" == "" ]; then
    echo "APT name is missing!"
    return
  fi

  set_default_config
  #yes/no for APT or non-APT alert            
  #Is this test a Positive/Negative one
  echo "TEST_DESC=\"Positive test\""                   >> ${TEST_CONFIG_FILE}
  echo "TEST_IS_APT=yes"                               >> ${TEST_CONFIG_FILE}
  echo "TEST_APT_NAME=$2"                              >> ${TEST_CONFIG_FILE}
  run_testcase_single_alert "$1"

}

######################################################################
#  function run_testcase_invalid_json_txt_file()
######################################################################
function run_testcase_invalid_json_txt_file(){
  #Single alert test
  set_default_config
  #run_testcase_single_alert "domain-match"
  RANDOM_TXT_FILE="random.txt"

  CURL=/usr/bin/curl

  echo "Sending curl command..."
  echo "${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --data-binary @${RANDOM_TXT_FILE} ${FIREEYE_ZONE_URL}"
  ${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --data-binary @${RANDOM_TXT_FILE} ${FIREEYE_ZONE_URL}
  echo "...Done"

}

######################################################################
#  function run_testcase_invalid_json_binary_file()
######################################################################
function run_testcase_invalid_json_binary_file(){
  #Single alert test
  set_default_config
  #run_testcase_single_alert "domain-match"
  RANDOM_BIN_FILE="random.png"

  CURL=/usr/bin/curl

  echo "Sending curl command..."
  echo "${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --data-binary @${RANDOM_BIN_FILE} ${FIREEYE_ZONE_URL}"
  ${CURL} -k -g --user ${FIREEYE_ADMINGROUP_USER}:${FIREEYE_ADMINGROUP_PASSWORD} --data-binary @${RANDOM_BIN_FILE} ${FIREEYE_ZONE_URL}
  echo "...Done"

}

######################################################################
#  function run_testcase_utf8_values_malware-callback()
######################################################################
function run_testcase_utf8_values_malware-callback(){

  #Single alert test
  set_default_config

  echo "TEST_ALERT_SEVERITY=嚴重"                       >> ${TEST_CONFIG_FILE} 
  #notified/blocked                   
  #echo "TEST_ALERT_ACTION=notified"                    >> ${TEST_CONFIG_FILE}              
  echo "TEST_ALERT_ACTION=阻止"                      >> ${TEST_CONFIG_FILE}              
  
  run_testcase_single_alert "malware-callback"

}

######################################################################
#  function run_testcase_single_alert_sql_injection()
######################################################################
function run_testcase_single_alert_sql_injection(){
  if [ "$1" != "" ]; then
    infection_type=$1
    echo "TEST_ALERT_NAME=${infection_type}"             >> ${TEST_CONFIG_FILE} 
  else
    echo "Input params incomplete!"
    return
  fi

  if [ "$2" != "" ]; then
    echo "TEST_ALERT_ID=$2"                              >> ${TEST_CONFIG_FILE}     
  else
    TimeStamp=$(get_timestamp)
    echo "TEST_ALERT_ID=${infection_type}_${TimeStamp}"  >> ${TEST_CONFIG_FILE} 
  fi

  echo "====Begin of test execution=================================="
  echo "----Begin of test config--------"
  cat ${TEST_CONFIG_FILE}
  echo "----End of test config----------"

  . ${TEST_CONFIG_FILE}

  echo "Executing test for ${TEST_ALERT_NAME} alert with Alert ID: ${TEST_ALERT_ID} ..."

  #JSON file
  if [ "${TEST_IS_APT}" == "yes" ]; then
   FILENAME_APT_SUBSTRING="_apt"
  fi
  FILENAME_NOTIFICATION_IN_JSON="${TEST_ALERT_NAME}${FILENAME_APT_SUBSTRING}_${TEST_MULTIPLE_OR_SINGLE}.json"

  create_json_file ${FILENAME_NOTIFICATION_IN_JSON} #${TEST_ALERT_NAME} ${TEST_IS_APT} ${TEST_MULTIPLE_OR_SINGLE} ${FIREEYE_APPLIANCE} ${TEST_ALERT_ID} ${TEST_ALERT_SEVERITY} ${TEST_ALERT_ACTION} ${TEST_INCLUDE_AT_SIGN}

  run_curl_command #${TEST_ALERT_NAME} ${TEST_IS_APT} ${TEST_MULTIPLE_OR_SINGLE} ${FIREEYE_APPLIANCE} ${TEST_ALERT_ID} ${TEST_ALERT_SEVERITY} ${TEST_ALERT_ACTION} ${TEST_INCLUDE_AT_SIGN}

  echo "Done with test for ${TEST_ALERT_NAME} alert."
  echo "====End of test execution===================================="

}

######################################################################
#  function run_testcase_sql_injection()
######################################################################
function run_testcase_sql_injection(){

  #Single alert test
  set_default_config         
  
  run_testcase_single_alert_sql_injection "malware-callback"

}



