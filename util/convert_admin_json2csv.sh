#!/bin/bash -eu

DIR_NAME=$(dirname $0)

# column
echo "user_arn,has_user_admin,has_grorup_admin,enable_permission_boundory" > ${DIR_NAME}/admin.csv

# convert by jq
cat ${DIR_NAME}/admin.json | jq -r '.[][] | [.user_arn, .has_user_admin, .has_grorup_admin, .enable_permission_boundory]|@csv' >> ${DIR_NAME}/admin.csv
