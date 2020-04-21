#!/bin/bash -eu

DIR_NAME=$(dirname $0)

# column
echo "user_arn, user_name, access_key_id_1, access_key_id_2, has_user_admin, has_grorup_admin, enable_permission_boundory" > ${DIR_NAME}/admin.csv

# convert by jq
cat ${DIR_NAME}/admin.json | jq -r '.[][] | [.user_arn, .user_name, .access_key_id[0], .access_key_id[1], .has_user_admin, .has_grorup_admin, .enable_permission_boundory]|@csv' >> ${DIR_NAME}/admin.csv
