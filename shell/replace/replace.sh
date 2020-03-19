#!/bin/sh

# Parameter
BEFORE=`cat FE |grep 'address'|awk 'NR==1{print}'|awk {'print $2'}`
AFTER=$1
FILENAME=FE


# Replace Text
sed "s/${BEFORE}/${AFTER}/g"  ${FILENAME} > ${FILENAME}.tmp


# Replace File
cat ${FILENAME}.tmp > ${FILENAME}
rm ${FILENAME}.tmp
