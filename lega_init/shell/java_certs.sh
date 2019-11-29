#!/usr/bin/env bash

set -e

[ "${BASH_VERSINFO[0]}" -lt 4 ] && echo 'Bash 4 (or higher) is required' 1>&2 && exit 1

if ! [ -x "$(command -v keytool)" ]; then
  echo 'Error: Keytool is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v openssl)" ]; then
  echo 'Error: Openssl is not installed.' >&2
  exit 1
fi

HERE=$(dirname "${BASH_SOURCE[0]}")
CONFPATH=$HERE/config
STORETYPE=PKCS12
STOREPASS=changeit

# list of known Java based services
services=(
    dataedge
    filedatabase
    keys
    res
    doa
    htsget
)  

function usage {
    echo "Usage: $0 [options]"
    echo -e "\nOptions are:"
    echo -e "\t--config-path <value>     \tPath for the configuration directory, [Default] is ${CONFPATH} folder"
    echo -e "\t--storetype <value>       \tType of certificate to create, JKS or PKCS12, [Default] is ${STORETYPE}"
    echo -e "\t--storepass <value>       \tThe password for the keystore, [Default] is ${STOREPASS}"
    echo -e "\t--help, -h               \tOutputs this message and exits"
    echo -e "\t-- ...                   \tAny other options appearing after the -- will be ignored"
    echo ""
}

# While there are arguments or '--' is reached
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage; exit 0;;
        --config-path) CONFPATH=$2; shift;;
        --storetype) STORETYPE=${2^^}; shift;;
        --storepass) STOREPASS=$2; shift;;
        --) shift; break;;
        *) echo "$0: error - unrecognized option $1" 1>&2; usage; exit 1;;
    esac
    shift
done

# remove previous alias if keystore exists
# becomes problemantic if password changed
if [[ -f "${CONFPATH}"/certs/cacerts ]]; then
    keytool -delete -alias legaCA \
            -keystore "${CONFPATH}"/certs/cacerts \
            -storepass "${STOREPASS}" -noprompt
fi 

# create java keystore for each service
for service in "${services[@]}"; do
    if [[ "${STORETYPE}" == "JKS" ]]; then
        openssl x509 -outform der -in "${CONFPATH}"/certs/"${service}".ca.crt \
                                  -out "${CONFPATH}"/certs/"${service}".ca.der
        keytool -import -alias "${service}" \
                -keystore "${CONFPATH}/certs/${service}.jks" \
                -file "${CONFPATH}"/certs/"${service}".ca.der \
                -storepass "${STOREPASS}" -noprompt
    else
        openssl pkcs12 -export -out "${CONFPATH}"/certs/"${service}".p12 \
                       -inkey "${CONFPATH}"/certs/"${service}".ca.key \
                       -in "${CONFPATH}"/certs/"${service}".ca.crt \
                       -passout pass:"${STOREPASS}"
    fi
done 

# create java CAroot truststore
keytool -import -trustcacerts -file "${CONFPATH}"/certs/root.ca.crt \
        -alias legaCA -storetype JKS \
        -keystore "${CONFPATH}"/certs/cacerts \
        -storepass "${STOREPASS}" -noprompt
