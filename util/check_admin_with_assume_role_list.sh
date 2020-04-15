#!/bin/bash -eu

# output sample
# {
#   "<assume_role>": [
#     {
#       "user_arn": "arn:aws:iam::<your_aws_account_id>:user/user_name",
#       "has_user_admin": true,
#       "has_grorup_admin": true,
#       "enable_permission_boundory": true
#     }
#   ]
# }

DIR_NAME=$(dirname $0)

# init
echo -n "" > ${DIR_NAME}/admin.json

# load
. ${DIR_NAME}/../env.sh

# exec
FIRST="true"
while read line; do
  RESULT=""
  echo "check with ${line}"
  export ASSUME_ROLE_ARN="${line}" 

  set +e
  RESULT=`${DIR_NAME}/../bin/aws-check-cli admin-check --admin-only`
  if [ $? -gt 0 ]; then
    continue
  fi
  set -e

  if [ -n "${RESULT}" ]; then
    if [ "${FIRST}" = "true" ]; then
      echo "{" >> ${DIR_NAME}/admin.json
      FIRST="false"
    else
      echo "," >> ${DIR_NAME}/admin.json
    fi
    echo -n "\"${line}\": ${RESULT}" >> ${DIR_NAME}/admin.json
  fi
done < ${DIR_NAME}/assume_role_list.txt

# finaly
if [ "${FIRST}" != "true" ]; then
  echo -ne "\n}\n" >> ${DIR_NAME}/admin.json
fi
