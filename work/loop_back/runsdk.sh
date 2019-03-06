#!/bin/sh

pon_mode=`flash get PON_MODE`
fiber_mode=`flash get FIBER_MODE | sed 's/FIBER_MODE=//g'`
if [ "$pon_mode" == "PON_MODE=1" ]; then
	if [ ! -f /var/config/run_customized_sdk.sh ]; then
		cp /etc/run_customized_sdk.sh /var/config/run_customized_sdk.sh
	fi
		/var/config/run_customized_sdk.sh
		/etc/runomci.sh
                /bin/pondetect 1&
		echo "running GPON mode ..."
elif [ "$pon_mode" == "PON_MODE=2" ]; then
        insmod /lib/modules/epon_drv.ko
        /etc/runoam.sh
        insmod /lib/modules/epon_polling.ko
        insmod /lib/modules/epon_mpcp.ko
        sleep 2
        /bin/pondetect 2&
        echo "running EPON mode ..."
elif [ "$pon_mode" == "PON_MODE=3" ]; then
        echo $fiber_mode > proc/fiber_mode
elif echo $pon_mode | grep -q "GET fail"; then
        echo $fiber_mode > proc/fiber_mode
else
        echo "running Ether mode..."
fi

insmod /lib/modules/rldp_drv.ko

