#!/bin/bash


# =================================================================================================================
# Usage:
# -----------------------------------------------------------------------------------------------------------------
usage() {
  cat <<-EOF
  A helper script to get the secrcts from 1password' vault.
  Usage: ./1pass.sh [-h -d <subdomainName> -u <accountName>]
                      -k <secretKey>
                      -p <masterPassword>
                      -m <method>
                      -e <environment(s)>
                      -v <vaultDetails>
                      -a <appName>
                      -n <namespace>
                      -s <skip>

  OPTIONS:
  ========
    -h prints the usage for the script.
    -d The subdomain name of the 1password account, default is registries.1password.ca.
    -u The account name of the 1password account, default is bcregistries.devops@gmail.com.
    -k The secret key of the 1password account.
    -p The master password of the 1password account.
    -m The methodof using the vaults.
        secret - set vault values to Openshift secrets
        env - set vault values to github action environment
        compare - compare two environments vault values
    -e The environment(s) of the vault, for example pytest/dev/test/prod or "dev test".
    -a Openshift application name, for example: auth-api-dev
    -n Openshift namespace name, for example: 1rdehl-dev
    -s Skip this script, for exmaple: true t TRUE T True 1
    -v A list of vault and application name of the 1password account, for example:
       [
          {
              "vault": "shared",
              "application": [
                  "keycloak",
                  "email"
              ]
          },
          {
              "vault": "relationship",
              "application": [
                  "auth-api",
                  "notify-api",
                  "status-api"
              ]
          }
      ]

EOF
exit
}

# -----------------------------------------------------------------------------------------------------------------
# Initialization:
# -----------------------------------------------------------------------------------------------------------------
while getopts h:a:d:u:k:p:v:m:e:n:s: FLAG; do
  case $FLAG in
    h ) usage ;;
    a ) APP_NAME=$OPTARG ;;
    d ) DOMAIN_NAME=$OPTARG ;;
    u ) USERNAME=$OPTARG ;;
    k ) SECRET_KEY=$OPTARG ;;
    p ) MASTER_PASSWORD=$OPTARG ;;
    v ) VAULT=$OPTARG ;;
    m ) METHOD=$OPTARG ;;
    e ) ENVIRONMENT=$OPTARG ;;
    n ) NAMESPACE=$OPTARG ;;
    s ) SKIP=$OPTARG ;;
    \? ) #unrecognized option - show help
      echo -e \\n"Invalid script option: -${OPTARG}"\\n
      usage
      ;;
  esac
done

# Shift the parameters in case there any more to be used

shift $((OPTIND-1))
# echo Remaining arguments: $@

skip_true=(true t TRUE T True 1)
if [[ " ${skip_true[@]} " =~ " ${SKIP} " ]]; then
  echo -e "Skip"
  exit
fi

if [ -z "${DOMAIN_NAME}" ]; then
  DOMAIN_NAME=registries.1password.ca
fi

if [ -z "${USERNAME}" ]; then
  USERNAME=bcregistries.devops@gmail.com
fi

if [ -z "${SECRET_KEY}" ] || [ -z "${MASTER_PASSWORD}" ]; then
  echo -e \\n"Missing parameters - secret key or master password"\\n
  usage
fi

if [ -z "${ENVIRONMENT}" ]; then
  echo -e \\n"Missing parameters - environment"\\n
  usage
fi

if [ -z "${VAULT}" ]; then
  echo -e \\n"Missing parameters - vault"\\n
  usage
fi

methods=(secret env compare)
if [[ ! " ${methods[@]} " =~ " ${METHOD} " ]]; then
  echo -e \\n"Method must be contain one of the following method: secret, env or compare."\\n
  usage
fi

envs=(${ENVIRONMENT})
if [[ " compare " =~ " ${METHOD} " ]]; then
  if [[ ${#envs[@]} != 2 ]]; then
    echo -e \\n"Environments must be contain two values ('dev test' or 'test prod')."\\n
    exit
  fi
fi

if [[ " secret " =~ " ${METHOD} " ]]; then
  if [[ -z "${APP_NAME}" ]]; then
    echo -e \\n"Missing parameters - application name"\\n
    usage
  else
    if [[ -z "${NAMESPACE}" ]]; then
      echo -e \\n"Missing parameters - namespace"\\n
      usage
    fi
  fi
fi


