#!/bin/bash
#
# usage: config-xmlconfig.sh [option] ...
#

DEFAULT_FILE="/etc/config_default.xml"
DEFAULT_HS_FILE="/etc/config_default_hs.xml"
LASTGOOD_FILE="/var/config/lastgood.xml"
HIDDEN_FILE="/var/config/hidden.xml"
LASTGOOD_HS_FILE="/var/config/lastgood_hs.xml"
FAIL_FILE_SUFFIX=".check_failed"
MP_HS_FILE="/var/config/lastgood_mp_hs.xml"
MP_HS_FILE2="/var/config/lastgood_mp_hs2.xml"
STATIC_HS_FILE="/var/config_static/lastgood_hs.xml"
HIDDEN_HS_FILE="/var/config/hidden_hs.xml"
HIDDEN_MP_HS_FILE="/var/config/hidden_mp_hs.xml"
HIDDEN_MP_HS_FILE2="/var/config/hidden_mp_hs2.xml"
CONFIGD_RUNFILE="/var/run/configd.pid"
PROVINCE_DIR="/etc/province/config"
HW_PROVINCE_NAME="HW_PROVINCE_NAME"
SHELL_NAME="bash"
BACKUP_SUFFIX="bak"
ONGOING_LOCK="/tmp/lock_ongoing."
WAITING_LOCK="/tmp/lock_waiting."

CPU_HIGH_LOADING="80"

ignoreOnHighLoad(){
        cpuload=$(top -n 1 | awk '/^CPU:/ {print $2}')
        cpuload=${cpuload%.*}
        [ "${cpuload}" -ge "0" ] || echo "[xml_ERR]: Get CPU info fail!"
        if [ "${cpuload}" -ge "${CPU_HIGH_LOADING}" ]; then
                echo "[xml_INFO]: CPU on high loading!"
                exit 0
        fi
}

waitOngoingLock(){
        lock_name=$1
        index=0
        while [ ${index} -le 10  ]
        do
                if mkdir "${ONGOING_LOCK}${lock_name}"  2> /dev/null
                then
                        return 0
                fi
                sleep 1
                index=$(( ++index ))
        done
        return 1
}

lockWorkingProcess(){
        lock_name=$1
        if mkdir "${WAITING_LOCK}${lock_name}" 2> /dev/null
        then
                trap 'rm -rf "${WAITING_LOCK}${lock_name}"; exit $?' INT TERM EXIT
                if  waitOngoingLock "${lock_name}"
                then
                        rm -rf "${WAITING_LOCK}${lock_name}"
                        trap - INT TERM EXIT
                        trap 'rm -rf "${ONGOING_LOCK}${lock_name}"; exit $?' INT TERM EXIT
                        return 0
                else
                        echo "Wait Ongoing lock Timeout!"
                        rm -rf "${WAITING_LOCK}${lock_name}"
                        trap - INT TERM EXIT
                        exit 1
                fi
        else
                echo "Not get waiting lock!"
                # not acquire the waiting lock
                exit 0
        fi
}


unlockWorkingProcess(){
        lock_name=$1
        ret="$?"
        rm -rf "${ONGOING_LOCK}${lock_name}"
        trap - INT TERM EXIT
        return ${ret}
}


check_space(){
        if [ "${1}" = "" -o ! -f ${1} ]; then
                _FILE_PATH="/var/config"
                file_size=100
        else
                _FILE_NAME="${1}"
                _FILE_PATH=${_FILE_NAME%/*}
                output_result=$(ls -s ${_FILE_NAME} )
                set ${output_result}
                file_size=${1}
        fi
        output_result=$( df ${_FILE_PATH} )
        set ${output_result}
        space_size=${11}
        whole_space=${9}
        if [ "${whole_space}" -gt "1000" ]; then
                file_size=`expr ${file_size} + ${file_size}`
        fi
        if [ ${space_size} -lt ${file_size} -o ${space_size} = "0" ]; then
                echo "FATAL ERROR: Not enough space ${space_size}/${file_size}"
                return  1
        fi
        return 0
}

genBackup(){
        fn="${1}"
        [ -f "${fn}" ] && check_space "${fn}" && /bin/xmlconfig -c "${fn}" > /dev/null && cp -f "$fn" "${fn}_${BACKUP_SUFFIX}" >  /dev/null
}

get_cmp_tool(){
        if [ -f "/bin/cmp" ]; then
                echo "/bin/cmp"
                return 0
        elif [ -f "/bin/diff" ]; then
                echo "/bin/diff"
                return 0
        fi
        return -1
}

chkBackup(){
        fn="${1}"
        cmp_tool=$( get_cmp_tool )
        if [ "$?" != "0" ]; then
                echo "msg: not cmp tool!"
                return -1
        fi

        if [ -f "${fn}" -a -f "${fn}_${BACKUP_SUFFIX}" ]; then
                cmp_str=$( ${cmp_tool} "$fn" "${fn}_${BACKUP_SUFFIX}" 2> /dev/null )
                if [ "${cmp_str}" != "" ]; then
                        cp -f "$fn" "${fn}_${BACKUP_SUFFIX}" && echo "Renew [${fn##*/}] backup file!"
                fi
        fi
        return 0
}

getProvinceConfigName() {
        ctc_prov=$(/bin/xmlconfig -g ${HW_PROVINCE_NAME} 2> /dev/null | sed "s/${HW_PROVINCE_NAME}=//")
        if [  ${ctc_prov:0:3} = "GET" ]; then
                ctc_prov='default'
        fi
        cfg_file=${PROVINCE_DIR}_${ctc_prov}.xml
        echo ${cfg_file}
}

genLastgood () {
        fn=$1
        result=$(/bin/xmlconfig -of -hid ${fn}) || /bin/xmlconfig -of ${fn}
}

genHiddenIfHidSuccess() {
        fn1=$1
        fn2=$2
        result=$(/bin/xmlconfig -of -hid ${fn1})
        [ "$?" == "0" ] && /bin/xmlconfig -of ${fn2} || /bin/xmlconfig -of ${fn1}
}

genLastgoodHs () {
        fn=$1
        result=$(/bin/xmlconfig -of -hs -hid ${fn}) || /bin/xmlconfig -of -hs ${fn}
}

genHiddenHsIfHidSuccess() {
        fn1=$1
        fn2=$2
        result=$(/bin/xmlconfig -of -hs -hid ${fn1})
        [ "$?" == "0" ] && /bin/xmlconfig -of -hs ${fn2} || /bin/xmlconfig -of -hs ${fn1}
}

loadLastgoodBackup(){
        [ -f ${LASTGOOD_FILE}_${BACKUP_SUFFIX} ] && /bin/xmlconfig -c ${LASTGOOD_FILE}_${BACKUP_SUFFIX} 2> /dev/null
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_FILE -if ${LASTGOOD_FILE}_${BACKUP_SUFFIX}  && genLastgood "${LASTGOOD_FILE}"
                if [ "$?" = '0' ]; then
                        echo "[xml_INFO]: Restore First Backup"
                        return 0
                fi
        fi
        return 1
}

loadHiddenBackup(){
        [ -f ${HIDDEN_FILE} ] || return 0
        [ -f ${HIDDEN_FILE}_${BACKUP_SUFFIX} ] && /bin/xmlconfig -c ${HIDDEN_FILE}_${BACKUP_SUFFIX} 2> /dev/null
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_FILE -if ${HIDDEN_FILE}_${BACKUP_SUFFIX}  && /bin/xmlconfig -of ${HIDDEN_FILE}
                if [ "$?" = '0' ]; then
                        echo "[xml_INFO]: Restore First Hidden Backup"
                        return 0
                fi
        fi
        return 1
}

loadLastgoodHsBackup(){
        [ -f ${LASTGOOD_HS_FILE}_${BACKUP_SUFFIX} ] && /bin/xmlconfig -c ${LASTGOOD_HS_FILE}_${BACKUP_SUFFIX} 2> /dev/null
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${LASTGOOD_HS_FILE}_${BACKUP_SUFFIX}  && genLastgoodHs $LASTGOOD_HS_FILE
                if [ "$?" = '0' ]; then
                        echo "[xml_INFO]: Restore First HS Backup"
                        return 0
                fi
        fi
        return 1
}

loadHiddenHsBackup(){
        [ -f ${HIDDEN_HS_FILE}_${BACKUP_SUFFIX} ] && /bin/xmlconfig -c ${HIDDEN_HS_FILE}_${BACKUP_SUFFIX} 2> /dev/null
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${HIDDEN_HS_FILE}_${BACKUP_SUFFIX}  && /bin/xmlconfig -of -hs $HIDDEN_HS_FILE
                if [ "$?" = '0' ]; then
                        echo "[xml_INFO]: Restore First Hidden HS Backup"
                        return 0
                fi
        fi
        return 1
}

loadMpLastgoodHsTwo(){
        [ -f ${MP_HS_FILE2} ] && /bin/xmlconfig -c ${MP_HS_FILE2}
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${MP_HS_FILE2}  && genLastgoodHs $LASTGOOD_HS_FILE
                if [ "$?" = '0' ]; then
                        echo "[xml_INFO]: Restore MP HS2 Backup"
                        return 0
                else
                        return 1
                fi
        else
                return 1
        fi
}

loadStaticLastgoodHsWhenFail() {
        if [ "$?" != '0' ]; then
                [ -f ${STATIC_HS_FILE} ] && /bin/xmlconfig -c ${STATIC_HS_FILE}
                if [ "$?" = '0' ]; then
                        /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${STATIC_HS_FILE}  && /bin/xmlconfig -of -hs $LASTGOOD_HS_FILE
                        if [ "$?" = '0' ]; then
                                echo "[xml_INFO]: Restore from static HS"
                                return 0
                        else
                                return $?
                        fi
                else
                        return $?
                fi
        fi
        return 0
}

loadMpHiddenHsTwo(){
        [ -f ${HIDDEN_MP_HS_FILE2} ] && /bin/xmlconfig -c ${HIDDEN_MP_HS_FILE2}
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${HIDDEN_MP_HS_FILE2}  && /bin/xmlconfig -of -hs $HIDDEN_HS_FILE
                if [ "$?" = '0' ]; then
                        echo "[xml_INFO]: Restore Hidden MP HS2 Backup"
                        return 0
                else
                        return 1
                fi
        else
                return 1
        fi
}


loadMpLastgoodHsWhenFail(){
        if [ "$?" != '0' ]; then
                [ -f ${MP_HS_FILE} ] && /bin/xmlconfig -c ${MP_HS_FILE}
                if [ "$?" = '0' ]; then
                        /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${MP_HS_FILE}  && genLastgoodHs $LASTGOOD_HS_FILE
                        if [ "$?" = '0' ]; then
                                echo "[xml_INFO]: Restore MP HS Backup"
                                return 0
                        else
                                loadMpLastgoodHsTwo
                                loadStaticLastgoodHsWhenFail
                                return $?
                        fi
                else
                        loadMpLastgoodHsTwo
                        loadStaticLastgoodHsWhenFail
                        return $?
                fi
        fi
        return 0
}

loadMpHiddenHsWhenFail() {
        if [ "$?" != '0' ]; then
                [ -f ${HIDDEN_MP_HS_FILE} ] && /bin/xmlconfig -c ${HIDDEN_MP_HS_FILE}
                if [ "$?" = '0' ]; then
                        /bin/xmlconfig -def $DEFAULT_HS_FILE -if ${HIDDEN_MP_HS_FILE}  && /bin/xmlconfig -of -hs $HIDDEN_HS_FILE
                        if [ "$?" = '0' ]; then
                                echo "[xml_INFO]: Restore MP Hidden HS Backup"
                                return 0
                        else
                                loadMpHiddenHsTwo
                                return $?
                        fi
                else
                        loadMpHiddenHsTwo
                        return $?
                fi
        fi
        return 0
}

genMpLastgoodHsTwo(){
        [ -f ${MP_HS_FILE} ] && /bin/xmlconfig -c ${MP_HS_FILE} > /dev/null
        if [ "$?" != "0" ]; then
                [ -f ${MP_HS_FILE2} ] && /bin/xmlconfig -c ${MP_HS_FILE2} > /dev/null
                if [ "$?" != "0" ]; then
                        cp ${LASTGOOD_HS_FILE} ${MP_HS_FILE2} && echo "Prepare the MP HS 2 OK"
                fi
        fi
        if [ -f /var/config/flash_def_cs ]; then
                echo "=======================> Reset to default <============================"
                [ -f ${LASTGOOD_FILE} ] && rm ${LASTGOOD_FILE}
                [ -f ${LASTGOOD_FILE}_${BACKUP_SUFFIX} ] && rm ${LASTGOOD_FILE}_${BACKUP_SUFFIX}
                rm /var/config/flash_def_cs
        fi
}

genMpHiddenHsTwo() {
        [ -f ${HIDDEN_MP_HS_FILE} ] || return 0
        [ -f ${HIDDEN_HS_FILE} ]    || return 0;
        result=$(/bin/xmlconfig -c ${HIDDEN_MP_HS_FILE})
        if [ "$?" != 0 ]; then
                [ -f ${HIDDEN_MP_HS_FILE2} ] && /bin/xmlconfig -c ${HIDDEN_MP_HS_FILE2} > /dev/null
                if [ "$?" != "0" ]; then
                        cp ${HIDDEN_HS_FILE} ${HIDDEN_MP_HS_FILE2} && echo "Prepare the Hidden MP HS 2 OK"
                fi
        fi
}

preserveFail(){
        fname=$1
        if [ -f ${fname} ]; then
                cp ${fname} ${fname}${FAIL_FILE_SUFFIX}
        fi
}

CheckProvinceUpdate(){
        cfg_province=`nv getenv cfg_province`
        if [[ $? -eq 0 ]] && [[ ! "${cfg_province}" == "" ]]; then
                cfg_province=${cfg_province/*=/}
                cfg=/etc/province/config_${cfg_province}.xml
                if [ -f ${cfg} ] ; then
                        echo "=======================> Update province [$cfg_province] <============================"
                        ##sed -i 's/<Value Name="HW_PROVINCE_NAME" Value=".*"\/>/<Value Name="HW_PROVINCE_NAME" Value="'${cfg_province}'"\/>/g' /var/config/lastgood_hs.xml
                        /bin/xmlconfig -s HW_PROVINCE_NAME ${cfg_province}
                        if [ $? -eq 0 ]; then
                                echo "reset to default"
                                ##[ -f /etc/config/lastgood_mp_hs2.xml ] && rm /etc/config/lastgood_mp_hs2.xml
                                [ -f ${LASTGOOD_FILE} ] && rm ${LASTGOOD_FILE}
                                [ -f ${LASTGOOD_FILE}_${BACKUP_SUFFIX} ] && rm ${LASTGOOD_FILE}_${BACKUP_SUFFIX}
                                nv setenv cfg_province
                        fi
                fi
        fi
}

CheckResetDefault(){
        rst2dfl=`nv getenv rst2dfl`
        if [[ $? -eq 0 ]] && [[ ! "${rst2dfl}" == "" ]]; then
                rst2dfl=${rst2dfl/*=/}
                if [[ $rst2dfl == 1 ]] ; then
                        echo "=======================> Reset to default <============================"
                        [ -f ${LASTGOOD_FILE} ] && rm ${LASTGOOD_FILE}
                        [ -f ${LASTGOOD_FILE}_${BACKUP_SUFFIX} ] && rm ${LASTGOOD_FILE}_${BACKUP_SUFFIX}
                        nv setenv rst2dfl
                fi
        fi
}

loadHiddenHs () {
        [ -f $HIDDEN_HS_FILE ] || return 0
        /bin/xmlconfig -c $HIDDEN_HS_FILE
        if [ "$?" == "0" ]; then
                /bin/xmlconfig -def $DEFAULT_HS_FILE -if $HIDDEN_HS_FILE
                genMpHiddenHsTwo
                chkBackup "${HIDDEN_HS_FILE}"
        else
                [ -f ${HIDDEN_HS_FILE} ] && loadHiddenHsBackup
                loadMpHiddenHsWhenFail
                if [ "$?" != "0" ]; then
                        /bin/xmlconfig -nodef -if $DEFAULT_HS_FILE && /bin/xmlconfig -of -hs $HIDDEN_HS_FILE
                fi
        fi
        if [ "$?" = '0' ]; then
                echo "[xml_INFO]: Load Hidden HS configuration success."
        else
                echo "[xml_ERR]: Load Hidden HS configuration FAIL."
        fi

}

loadHidden() {
        [ -f ${HIDDEN_FILE} ] || return 0
        /bin/xmlconfig -c $HIDDEN_FILE
        if [ "$?" == "0" ]; then
                /bin/xmlconfig -def $DEFAULT_FILE -if $HIDDEN_FILE
        else
                [ -f $HIDDEN_FILE ] && loadHiddenBackup
                if [ "$?" != '0' ]; then
                        cfg_file=$( getProvinceConfigName )
                        [ -f ${cfg_file} ] && /bin/xmlconfig -c $cfg_file
                        if [ "$?" = "0" ]; then
                                /bin/xmlconfig -nodef -if $DEFAULT_FILE && /bin/xmlconfig -nodef -if $cfg_file && /bin/xmlconfig -of $HIDDEN_FILE
                        else
                                /bin/xmlconfig -nodef -if $DEFAULT_FILE && /bin/xmlconfig -of $HIDDEN_FILE
                        fi
                fi
        fi
        if [ "$?" = '0' ]; then
                echo "[xml_INFO]: Load Hidden configuration success."
        else
                echo "[xml_ERR]: Load Hidden configuration FAIL."
                exit 1
        fi
}

case "$1" in
  "-b")
        echo "------ [$1]Bootup_config ------"
        wait_count=10
        while [  $wait_count -gt 0 ]; do
                [ -f $CONFIGD_RUNFILE ] && break
                echo "Wait for configd initialize 'MsgQ' and 'Shm'... "
                sleep 1
                wait_count=$(( $wait_count - 1 ))
        done
        [ -f $CONFIGD_RUNFILE ] || echo "WARNING: Configd has not finish initiation, xmlconfig may has some problem!"

        /bin/xmlconfig -def_mib && /bin/xmlconfig -def_mib -hs && echo "Pre-fetch mib data from program default done." || echo "Pre-fetch mib data from program default FAIL."
        loadHiddenHs
        [ -f $LASTGOOD_HS_FILE ]  && /bin/xmlconfig -c $LASTGOOD_HS_FILE
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_HS_FILE -if $LASTGOOD_HS_FILE
                genMpLastgoodHsTwo
                chkBackup "${LASTGOOD_HS_FILE}"
        else
                preserveFail ${LASTGOOD_HS_FILE}
                [ -f ${LASTGOOD_HS_FILE} ] && loadLastgoodHsBackup
                loadMpLastgoodHsWhenFail
                if [ "$?" != '0' ]; then
                        /bin/xmlconfig -nodef -if $DEFAULT_HS_FILE && genLastgoodHs $LASTGOOD_HS_FILE
                fi
        fi
        if [ "$?" = '0' ]; then
                echo "[xml_INFO]: Load HS configuration success."
                CheckResetDefault
                CheckProvinceUpdate
        else
                echo "[xml_ERR]: Load HS configuration FAIL."
        fi

        loadHidden

        [ -f $LASTGOOD_FILE ] && /bin/xmlconfig -c $LASTGOOD_FILE
        if [ "$?" = '0' ]; then
                /bin/xmlconfig -def $DEFAULT_FILE -if $LASTGOOD_FILE
        else
                preserveFail ${LASTGOOD_FILE}
                [ -f $LASTGOOD_FILE ] && loadLastgoodBackup
                if [ "$?" != '0' ]; then
                        cfg_file=$( getProvinceConfigName )
                        [ -f ${cfg_file} ] && /bin/xmlconfig -c $cfg_file
                        if [ "$?" = "0" ]; then
                                /bin/xmlconfig -nodef -if $DEFAULT_FILE && /bin/xmlconfig -nodef -if $cfg_file && genLastgood $LASTGOOD_FILE
                        else
                                /bin/xmlconfig -nodef -if $DEFAULT_FILE && genLastgood $LASTGOOD_FILE
                        fi
                fi
        fi
        if [ "$?" = '0' ]; then
                echo "[xml_INFO]: Load CS configuration success."
        else
                echo "[xml_ERR]: Load CS configuration FAIL."
                exit 1
        fi
        exit 0
        ;;
  "-c")
        echo "------ [$1]Check_config ------"
        if [ "$2" != "" ]; then
                /bin/xmlconfig -c $2
                if [ "$?" = "0" ]; then
                        echo "[xml_INFO]: The input configuration file is available."
                        exit 0
                fi
        else
                echo "[xml_ERR]: No input configuration file."
                /bin/$SHELL_NAME $0 -h
                exit 1
        fi
        echo "[xml_ERR]: The input configuration file is invalid."
        exit 1
        ;;
  "-d")
        echo "------ [$1]Default_config ------"
                cfg_file=$( getProvinceConfigName )
                [ -f ${cfg_file} ] && /bin/xmlconfig -c $cfg_file
                if [ "$?" = "0" ]; then
                        /bin/xmlconfig -def_mib && /bin/xmlconfig -if $DEFAULT_FILE -nodef && /bin/xmlconfig -nodef -if $cfg_file && genHiddenIfHidSuccess "$LASTGOOD_FILE" "$HIDDEN_FILE"
                else
                        /bin/xmlconfig -def_mib && /bin/xmlconfig -if $DEFAULT_FILE -nodef && genHiddenIfHidSuccess "$LASTGOOD_FILE" "$HIDDEN_FILE"
                fi
        if [ "$?" = "0" ]; then
                echo "[xml_INFO]: Reset to default configuration success, please reboot the system."
                exit 0
        else
                rm $LASTGOOD_FILE
                echo "[xml_ERR]: Reset to default configuration FAIL!!"
                echo "Sysyem has removed the current setting, please reboot to reset to default."
                exit 1
        fi
        ;;
  "-l")
        echo "------ [$1]Load_input_config ------"
        if [ "$2" != "" ] && [ -s $2 ]; then
                /bin/xmlconfig -c $2
                if [ "$?" != "0" ]; then
                        echo "[xml_ERR]: Check the configuration file FAIL!!"
                        exit 1
                fi
                genBackup "${LASTGOOD_FILE}"
                /bin/xmlconfig -def_mib && /bin/xmlconfig -def $DEFAULT_FILE -if $2
                cp $2 $LASTGOOD_FILE
                if [ "$?" = "0" ]; then
                        echo "[xml_INFO]: Load the configuration file success, please reboot the system."
                        exit 0;
                fi
        else
                echo "[xml_ERR]: No input configuration file."
                /bin/$SHELL_NAME $0 -h
        fi
        echo "[xml_ERR]: Upload the configuration file FAIL!! Need to Reboot~"
        exit 1
        ;;
  "-s")
        echo "------ [$1]Save_config ------"
        if [ "$2" != "" ]; then
                genLastgood $2 && /bin/xmlconfig -c $2
                if [ "$?" = "0" ]; then
                        echo "[xml_INFO]: Save cofiguration to $2 success."
                        exit 0
                fi
        else
                echo "[xml_ERR]: No input configuration file."
                /bin/$SHELL_NAME $0 -h
        fi
        echo "[xml_ERR]: Save cofiguration FAIL."
        exit 1
        ;;
  "-u" | "-u cs")
        ignoreOnHighLoad
        lockWorkingProcess "cs"
        echo "------ [$1]Update cs setting ------"
        genBackup "${LASTGOOD_FILE}"
        genBackup "${HIDDEN_FILE}"
        genHiddenIfHidSuccess "$LASTGOOD_FILE" "$HIDDEN_FILE"
        unlockWorkingProcess "cs"
        if [ "$?" = "0" ]; then
                echo "[xml_INFO]: Update cs configuration success."
                exit 0
        fi
        echo "[xml_ERR]: Update cs configuration FAIL!!"
        exit 1
        ;;
  "-u hs")
        lockWorkingProcess "hs"
        echo "------ [$1]Update hs setting ------"
        genBackup "${LASTGOOD_HS_FILE}"
        genBackup "${HIDDEN_HS_FILE}"
        genHiddenHsIfHidSuccess "${LASTGOOD_HS_FILE}" "${HIDDEN_HS_FILE}"
        unlockWorkingProcess "hs"
        if [ "$?" = "0" ]; then
                echo "[xml_INFO]: Update hs configuration success."
                exit 0
        fi
        echo "[xml_ERR]: Update hs configuration FAIL!!"
        exit 1
        ;;
        "-p")
                echo "------ [$1]Check_config ------"
                if [ "$2" != "" ]; then
                        cfg_file=${PROVINCE_DIR}_$2.xml
                        [ -f ${cfg_file} ] && /bin/xmlconfig -c $cfg_file
                        if [ "$?" = "0" ]; then
                                echo "[xml_INFO]: The input configuration file is available."
                                /bin/xmlconfig -nodef -if $cfg_file && genHiddenIfHidSuccess "$LASTGOOD_FILE" "$HIDDEN_FILE"
                                if [ "$?" = '0' ]; then
                                        echo "[xml_INFO]: Load PROVINCE configuration success."
                                else
                                        echo "[xml_ERR]: Load PROVINCE configuration FAIL."
                                        exit 1
                                fi
                                exit 0
                        else
                                echo "[xml_ERR]: No input configuration file."
                                /bin/$SHELL_NAME $0 -h
                                exit 1
                        fi
                else
                        echo "[xml_ERR]: insufficient arguments"
                        /bin/$SHELL_NAME $0 -h
                        exit 1
                fi
        ;;
  "-h")
        echo 'usage: config_xmlconfig.sh [option]...'
        echo 'options:'
        echo '  -h        : print this help'
        echo '  -b        : Boot up process with configuration file'
        echo '  -c <file> : Check input configuration file'
        echo '  -d        : Restore to default configuration'
        echo '  -l <file> : Load from input file'
        echo '  -s <file> : Save current configuration to specific file'
        echo '  -u cs/hs  : Update configuration to flash'
        echo '  -p <prov> : Load Province setting'
        ;;
  *)
        echo "[xml_ERR]: insufficient arguments"
        /bin/$SHELL_NAME $0 -h
        exit 1
        ;;
esac

