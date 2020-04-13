# aws-check-cli

## enviroment
- copy `env.sh` from `env_sample.sh`
```bash
$ cp env_sample.sh env.sh
$ vi env.sh
```

## check admin users
```bash
$ make check-admin
```

## check admin users to cross-account with assume-role
```bash
$ export ASSUME_ROLE_ARN="arn:aws:iam::123456789012:role/YOUR_ASSUME_ROLE_HERE" 
$ make check-admin
# show admin user on json format 
```
