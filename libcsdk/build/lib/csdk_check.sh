#!/bin/bash
pushd /var/persistent/config/csdk 1>/dev/null 2>&1
cat ./csdk_info
grep csdk_test ./csdk_info | /usr/bin/sha256sum --check --status
if [ $? -gt 0 ] ; then
    # bad checksum or file missing
    echo "Warning checksum failed!"
    exit 1
fi
grep libcsdk.so.0.0.4 ./csdk_info | /usr/bin/sha256sum --check --status
if [ $? -gt 0 ] ; then
    # bad checksum or file missing
    echo "Warning checksum failed!"
    exit 1
fi
popd 1>/dev/null 2>&1
echo "Checksums verified!"
exit 0
