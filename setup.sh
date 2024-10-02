#!/bin/bash

# Define variables
env_file="env.vars"
NETWORK_NAME="akeyless-network"
AKEYLESS_ACCOUNT_ID="acc-qwuumdbdxi1g" # Change me, only use if your email is associated with more than 1 account
GW_WEB="18888"
GW_CONF="8000"
GW_API="8081"
GW_HVP="8200"
GW_KMIP="5696"
GW_GRPC="8085"
OUTPUT_FILE="docker-compose.yml"
DOCKER_IMAGE_AKEYLESS="akeyless/base:latest-akeyless"
DOCKER_IMAGE_CUSTOM_SERVER="akeyless/custom-server"
DOCKER_IMAGE_ZTBASTION="akeyless/zero-trust-bastion:latest"
DOCKER_IMAGE_POSTGRESQL="bitnami/postgresql:latest"
DOCKER_IMAGE_GRAFANA="bitnami/grafana:latest"
CLI_PATH="${HOME}/.akeyless/bin"
CLI="$CLI_PATH/akeyless"
CLI_PROFILE="--profile email"
BASE_URL="https://akeyless-cli.s3.us-east-2.amazonaws.com/cli/latest/production"

# Functions
prompt_for_input() {
  local prompt_message=$1
  local var_name=$2
  local secret=$3  # Set this to 'true' if input is sensitive (e.g., passwords)
  
  if [ -z "${!var_name}" ]; then
    if [ "$secret" = "true" ]; then
      read -s -p "$prompt_message " input_value
      echo  # Moves to the next line after input (without showing input text)
    else
      read -p "$prompt_message " input_value
    fi
    export $var_name="$input_value"
    echo "$var_name=$input_value" >> "$env_file"
  else
    echo "$var_name is already set to ${!var_name}"
  fi
}

# Ensure required tools are installed
install_if_missing() {
    if ! command -v "$1" &> /dev/null; then
        echo "Installing $1..."
        eval "$2"
    else
        echo "$1 is already installed."
    fi
}

# Install necessary tools
install_if_missing "gh" "sudo apt-get update && sudo apt-get install gh -y"
install_if_missing "yq" "sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq >/dev/null 2>&1 && sudo chmod +x /usr/local/bin/yq"
install_if_missing "nc" "sudo apt-get install netcat -y"
install_if_missing "jq" "sudo apt-get install jq -y"
install_if_missing "akeyless" "mkdir -p '$CLI_PATH' && curl -o '$CLI_PATH/akeyless' $BASE_URL/cli-linux-amd64 && chmod +x '$CLI_PATH/akeyless' && '$CLI_PATH/akeyless' --init"
source ~/.bashrc
$CLI update

# Prompt user for LAB ID
prompt_for_input "Enter a friendly name for this lab (e.g., akeyless-lab):" LAB_ID
prompt_for_input "Enter the email address from your Akeyless console account:" admin_email
prompt_for_input "Enter the password for your Akeyless console account email login:" admin_password true  # Secret input
prompt_for_input "Enter POSTGRESQL_PASSWORD:" POSTGRESQL_PASSWORD true  # Secret input
prompt_for_input "Enter POSTGRESQL_USERNAME:" POSTGRESQL_USERNAME
prompt_for_input "Enter database target name:" DB_TARGET_NAME

echo "All required components are checked and installed if necessary."

# Configure CLI
"$CLI" configure --profile email --access-type password --admin-email "$admin_email" --admin-password "$admin_password" --account-id $AKEYLESS_ACCOUNT_ID >/dev/null 2>&1
echo "CLI configured..."
#Add akeyless CLI auto completion
sudo tee /etc/bash_completion.d/akeyless_completion >/dev/null <<'EOF'
_akeyless() 
{
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--help"
    [ $COMP_CWORD -gt 2 ] && return 0
    if [ "${prev}" == "akeyless" ]; then
        [ "${cur}" == "" ] || akeyless ${cur} 2>&1 | grep -Eqi "not found"
        if [ $? -eq 0 ]; then
            COMPREPLY=($(compgen -W "$(akeyless ${opts} | sed '1,17d' | awk '{print $1}')" -- "${COMP_WORDS[$COMP_CWORD]}"))
        fi 
    else
        COMPREPLY=($(compgen -W "$(akeyless ${prev} ${opts} | sed '1,4d' | sed 's/.*\-\-/\-\-/g' | sed 's/\[.*//g' | awk '{print $1}' | grep '^\-')" -- "${COMP_WORDS[$COMP_CWORD]}"))
    fi
    return 0
}
complete -F _akeyless akeyless
EOF

source /etc/bash_completion.d/akeyless_completion

#Cleanup
$CLI auth-method delete -n "/$LAB_ID/UIDAuth" $CLI_PROFILE
# Create Akeyless UID Auth Method using the Akeyless CLI
$CLI auth-method create universal-identity -n "/$LAB_ID/UIDAuth" --jwt-ttl 10
TOKEN=$("$CLI" uid-generate-token -n "/$LAB_ID/UIDAuth" | grep 'Token:' | awk '{print $NF}')
auth_methods_output=$("$CLI" list-auth-methods $CLI_PROFILE)
EMAIL_ACCESS_ID=$(echo "$auth_methods_output" | jq -r '.auth_methods[] | select(.access_info.rules_type == "email_pass") | .access_info.access_id_alias')
SAML_ACCESS_ID=$(echo "$auth_methods_output" | jq -r '.auth_methods[] | select(.access_info.rules_type == "saml2") | .auth_method_access_id')
ADMIN_ACCESS_ID=$(echo "$auth_methods_output" | jq -r '.auth_methods[] | select(.access_info.rules_type == "universal_identity") | .auth_method_access_id')

# Configure RBAC #NOTE EMAIL Profile is not secure.  Do not use this for production, replace with cloud-id or UID
CAPABILITIES=('create' 'read' 'update' 'delete' 'list')
capabilities_args=$(printf " --capability %s" "${CAPABILITIES[@]}")

ROLE_NAME="${LAB_ID}-role"
"$CLI" create-role --name "$ROLE_NAME" $CLI_PROFILE
"$CLI" set-role-rule --role-name "$ROLE_NAME" --path "/$LAB_ID/*" --rule-type role-rule $capabilities_args $CLI_PROFILE
"$CLI" set-role-rule --role-name "$ROLE_NAME" --path "/$LAB_ID/*" --rule-type target-rule $capabilities_args $CLI_PROFILE
"$CLI" set-role-rule --role-name "$ROLE_NAME" --path "/$LAB_ID/*" --rule-type auth-method-rule $capabilities_args $CLI_PROFILE
"$CLI" set-role-rule --role-name "$ROLE_NAME" --path "/$LAB_ID/*" --rule-type item-rule $capabilities_args $CLI_PROFILE
#associate the new role with the auth method
"$CLI" assoc-role-am --role-name "$ROLE_NAME" --am-name "/$LAB_ID/UIDAuth" $CLI_PROFILE

$CLI auth --access-type universal_identity --access-id $ADMIN_ACCESS_ID --uid_token $TOKEN $CLI_PROFILE
#rm -rf ~/.akeyless/profiles/email.toml

# Fetch the changelog
changelog=$(curl -s https://changelog.akeyless.io)

# Extract the last 5 versions
versions=$(echo "$changelog" | grep -Eo '^[ ]*[0-9]+\.[0-9]+\.[0-9]+' | head -n 5)

# Convert the versions into an array
version_array=($versions)

# Check if there are any versions found
if [ ${#version_array[@]} -eq 0 ]; then
    echo "No versions found."
    exit 1
fi

# Display the menu and allow the user to select a version
echo "Select a version:"
select version in "${version_array[@]}"; do
    if [[ -n $version ]]; then
        export GW_VERSION=$version
        echo "installing GW Version:  $GW_VERSION"
        break
    else
        echo "Invalid selection. Please try again."
    fi
done

# Generate docker-compose.yml
cat << EOF > $OUTPUT_FILE
networks:
  $NETWORK_NAME:
    driver: bridge
    external: true
services:
  Akeyless-Gateway:
    image: $DOCKER_IMAGE_AKEYLESS
    container_name: akeyless-gateway
    ports:
      - "$GW_CONF:$GW_CONF"
      - "8200:8200"
      - "18888:18888"
      - "8080:8080"
      - "8081:8081"
      - "5696:5696"
    environment:
      VERSION: $GW_VERSION
      CLUSTER_NAME: akeyless-lab
      CLUSTER_URL: "http://127.0.0.1:8000"
      ADMIN_ACCESS_ID: "$ADMIN_ACCESS_ID"
      ADMIN_UID_TOKEN: "$TOKEN"
      ALLOWED_ACCESS_PERMISSIONS: '[{"name":"SAML_ADMIN","access_id":"${SAML_ACCESS_ID}","permissions":["admin"]},{"name":"GW_ADMIN","access_id":"${ADMIN_ACCESS_ID}","permissions":["admin"]},{"name":"EMAIL_ADMIN","access_id":"${EMAIL_ACCESS_ID}","permissions":["admin"]}]'
    networks:
      - $NETWORK_NAME
  custom-server:
    image: $DOCKER_IMAGE_CUSTOM_SERVER
    container_name: custom-server
    ports:
      - "2608:2608"
    volumes:
      - $PWD/custom_logic.sh:/custom_logic.sh
    environment:
      GW_ACCESS_ID: "$ADMIN_ACCESS_ID"
    restart: unless-stopped
    networks:
      - $NETWORK_NAME
  zero-trust-bastion:
    image: $DOCKER_IMAGE_ZTBASTION
    container_name: akeyless-lab-web-bastion
    ports:
      - "8888:8888"
    environment:
      AKEYLESS_GW_URL: https://rest.akeyless.io
      PRIVILEGED_ACCESS_ID: "$ADMIN_ACCESS_ID"
      ALLOWED_ACCESS_IDS: "$SAML_ACCESS_ID"
    restart: unless-stopped
    networks:
      - $NETWORK_NAME
  postgresql:
    image: $DOCKER_IMAGE_POSTGRESQL
    container_name: postgresql
    ports:
      - "5432:5432"
    environment:
      POSTGRESQL_PASSWORD: "$POSTGRESQL_PASSWORD"
      POSTGRESQL_USERNAME: "$POSTGRESQL_USERNAME"
    networks:
      - $NETWORK_NAME
  grafana:
    image: $DOCKER_IMAGE_GRAFANA
    container_name: grafana
    ports:
      - "3000:3000"
    networks:
      - $NETWORK_NAME
EOF

echo "docker-compose.yml file has been generated at $OUTPUT_FILE."

# Kill existing docker containers
sudo docker stop $(sudo docker ps -aq) >/dev/null 2>&1
sudo docker rm $(sudo docker ps -aq) >/dev/null 2>&1

# Create docker network if it doesn't exist
sudo docker network create $NETWORK_NAME || echo "Network $NETWORK_NAME already exists."

# Run docker-compose up -d
sudo docker-compose up -d
echo "Docker containers are being started in detached mode."

# Wait for the containers to be up and running
echo "Waiting for the containers to be up and running..."
services=$(yq e '.services | keys' $OUTPUT_FILE | sed 's/- //g')
for service in $services; do
    echo "Checking service: $service"
    while ! [ "$(sudo docker-compose ps -q $service)" ] || ! [ "$(sudo docker inspect -f '{{.State.Running}}' $(sudo docker-compose ps -q $service))" == "true" ]; do
        echo "Waiting for $service to start..."
        sleep 5
    done
    echo "$service is up and running"
done

# Set environment variables for hostnames
export DB_HOST=$(sudo docker inspect --format '{{ .Name }}' $(sudo docker-compose ps -q postgresql) | sed 's/^\///')
export GRAFANA_HOST=$(sudo docker inspect --format '{{ .Name }}' $(sudo docker-compose ps -q grafana) | sed 's/^\///')
export CUSTOM_SERVER_HOST=$(sudo docker inspect --format '{{ .Name }}' $(sudo docker-compose ps -q custom-server) | sed 's/^\///')
export AKEYLESS_GATEWAY_HOST=$(sudo docker inspect --format '{{ .Name }}' $(sudo docker-compose ps -q Akeyless-Gateway) | sed 's/^\///')

# Check if akeyless-gateway is up
while ! nc -zv "$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $AKEYLESS_GATEWAY_HOST)" $GW_CONF; do
    echo "Waiting for akeyless-gateway to be up on port $GW_CONF..."
    sleep 10
done

# Target cleanup
$CLI target delete --name "/$LAB_ID/Databases/${DB_TARGET_NAME}" 
$CLI create-db-target --name "/$LAB_ID/Databases/${DB_TARGET_NAME}" --db-type postgres --pwd $POSTGRESQL_PASSWORD --host $DB_HOST --port 5432 --user-name $POSTGRESQL_USERNAME --db-name postgres
$CLI create-secret --name "/$LAB_ID/Static/dummy" --value MyStaticSecret
$CLI create-dfc-key -n "/$LAB_ID/Encryption/MyAES128GCMKey" -a AES128GCM
$CLI create-classic-key --name "/$LAB_ID/Encryption/Classickey" --alg RSA2048
# Attempt to create the DFC key
$CLI create-dfc-key --name "/$LAB_ID/Encryption/MyRSAKey" --alg RSA2048

create_status=$?

# If the DFC key didn't exist and was created, then create the SSH cert issuer
if [ $create_status -ne 0 ]; then
    $CLI create-ssh-cert-issuer --name "/$LAB_ID/SSH/SSH-ISSUER" --signer-key-name "/$LAB_ID/Encryption/MyRSAKey" --allowed-users 'ubuntu,root' --ttl 300 > /dev/null 2>&1
fi

$CLI rotated-secret create postgresql \
--name "/$LAB_ID/Rotated/${DB_TARGET_NAME}-rotate" \
--gateway-url "http://127.0.0.1:8000" \
--target-name "/$LAB_ID/Databases/${DB_TARGET_NAME}" \
--authentication-credentials use-target-creds \
--password-length 16 \
--rotator-type target \
--auto-rotate true \
--rotation-interval 1 \
--rotation-hour $ROTATION_HOUR


# Define the SQL statements for creating and revoking Super users
POSTGRESQL_STATEMENTS_SU=$(cat <<EOF
CREATE ROLE "{{name}}" WITH SUPERUSER CREATEDB CREATEROLE LOGIN ENCRYPTED PASSWORD '{{password}}';
EOF
)

POSTGRESQL_REVOKE_STATEMENT_SU=$(cat <<EOF
REASSIGN OWNED BY "{{name}}" TO {{userHost}};
DROP OWNED BY "{{name}}";
select pg_terminate_backend(pid) from pg_stat_activity where usename = '{{name}}';
DROP USER "{{name}}";
EOF
)

# Define the SQL statements for creating and revoking Read_Only
POSTGRESQL_STATEMENTS_RO=$(cat <<EOF
CREATE USER "{{name}}" WITH PASSWORD '{{password}}';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
GRANT CONNECT ON DATABASE postgres TO "{{name}}";
GRANT USAGE ON SCHEMA public TO "{{name}}";
EOF
)

POSTGRESQL_REVOKE_STATEMENT_RO=$(cat <<EOF
REASSIGN OWNED BY "{{name}}" TO {{userHost}};
DROP OWNED BY "{{name}}";
select pg_terminate_backend(pid) from pg_stat_activity where usename = '{{name}}';
DROP USER "{{name}}";
EOF
)

# Create Super User DB Dynamic Secret
$CLI dynamic-secret create postgresql \
--name "/$LAB_ID/Dynamic/${DB_TARGET_NAME}-su-dynamic" \
--target-name "/$LAB_ID/Databases/${DB_TARGET_NAME}" \
--gateway-url "http://127.0.0.1:8000" \
--postgresql-statements "$POSTGRESQL_STATEMENTS_SU" \
--postgresql-revoke-statement "$POSTGRESQL_REVOKE_STATEMENT_SU" \
--password-length 16 \
--uid-token $TOKEN

# Create Read_only DB Dynamic Secret
$CLI dynamic-secret create postgresql \
--name "/$LAB_ID/Dynamic/${DB_TARGET_NAME}-ro-dynamic" \
--target-name "/$LAB_ID/Databases/${DB_TARGET_NAME}" \
--gateway-url "http://127.0.0.1:8000" \
--postgresql-statements "$POSTGRESQL_STATEMENTS_RO" \
--postgresql-revoke-statement "$POSTGRESQL_REVOKE_STATEMENT_RO" \
--password-length 16 \
--uid-token $TOKEN
