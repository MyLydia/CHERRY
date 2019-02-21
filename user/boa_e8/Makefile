.EXPORT_ALL_VARIABLES:
SRCNAME = src-project
DIRS = $(SRCNAME)
RC_LEVEL_E8B=/etc/init.d/rc8
RC_LEVEL_FLASH_CHK=/etc/init.d/rc18
ifeq ($(CONFIG_GPON_FEATURE),y)
RC_LEVEL_CONFIGD=/etc/init.d/rc3
else
RC_LEVEL_CONFIGD=/etc/init.d/rc18
endif
ifeq ($(CONFIG_RTK_OAM_V1),y)
RC_LEVEL_STARTUP=/etc/init.d/rc32
else
RC_LEVEL_STARTUP=/etc/init.d/rc22
endif
RC_LEVEL_BOA=/etc/init.d/rc34

CFLAGS+=-Werror

## statck memory override debug
#CFLAGS += -g -O0 -fstack-protector-all 
#LDFLAGS += -lssp
#export CFLAGS LDFLAGS

#
# to add a new branch, please define new ID, SRCORIGNAME, and WEBNAME, all enclosed by ifeq
#
ID = default_web_id
SRCORIGNAME = src
WEBNAME = web_default
ifeq ($(CONFIG_CU),y)
WEBNAME = web_cu
else
ifeq ($(CONFIG_CMCC),y)
WEBNAME = web_cmcc
endif
endif

ifndef UCLINUX_BUILD_USER
include ../../config/.config
ifdef ROOTDIR
include $(ROOTDIR)/$(LINUXDIR)/.config
endif
endif

all romfs:
ifneq ($(ID),$(wildcard $(ID)))
	# remove symbolic links
	rm -rf $(SRCNAME)/web
	rm -rf $(SRCNAME)

	# add new symbolic links
	ln -s $(SRCORIGNAME) $(SRCNAME)
	cd $(SRCNAME); ln -s $(WEBNAME) web; cd ..

	make -C $(SRCNAME) clean

	# remove old IDs and touch the new ID
	rm -f *_id
	touch $(ID)
endif
	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done
ifdef CONFIG_USER_CONF_ON_XMLFILE
	$(ROMFSINST) $(ROOTDIR)/config/config_default.xml /etc/config_default.xml
	$(ROMFSINST) $(ROOTDIR)/config/config_default_hs.xml /etc/config_default_hs.xml
endif

.PHONY: rcX
rcX:
ifdef CONFIG_JFFS2_FS
ifdef CONFIG_BOA_WEB_E8B_CH
	$(ROMFSINST) -a "mount -t jffs2 /dev/mtdblock7 /usr/local/ct" $(RC_LEVEL_E8B)
endif
endif
ifdef CONFIG_BOA_WEB_E8B_CH
	$(ROMFSINST) -a "echo 200 > /proc/sys/vm/dirty_writeback_centisecs" $(RC_LEVEL_E8B)
	$(ROMFSINST) -a "echo 200 > /proc/sys/vm/dirty_expire_centisecs" $(RC_LEVEL_E8B)
endif
ifndef CONFIG_USER_XMLCONFIG
ifndef CONFIG_USER_CONF_ON_XMLFILE
	$(ROMFSINST) -a "/bin/flash check" $(RC_LEVEL_FLASH_CHK)
endif
endif

ifdef CONFIG_USER_XMLCONFIG
	$(ROMFSINST) -a "/etc/scripts/reset_default.sh" $(RC_LEVEL_CONFIGD)
endif
	$(ROMFSINST) -a "configd&" $(RC_LEVEL_CONFIGD)
ifdef CONFIG_E8B
	$(ROMFSINST) -a "cp /bin/ctadmin /usr/local/ct" $(RC_LEVEL_STARTUP)
endif
	$(ROMFSINST) -a "startup&" $(RC_LEVEL_STARTUP)



clean:
	# remove old IDs
	rm -f *_id;
	for i in $(DIRS) ; do make -C $$i clean ; done

