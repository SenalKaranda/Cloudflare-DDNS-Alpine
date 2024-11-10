#!/bin/sh
# Needs to be sh for Alpine

auth_email=""                                       # The email used to login 'https://dash.cloudflare.com'
auth_method="token"                                 # Set to "global" for Global API Key or "token" for Scoped API Token
auth_key=""                                         # Your API Token or Global API Key
zone_identifier=""                                  # Can be found in the "Overview" tab of your domain
record_name=""                                      # Which record you want to be synced
ttl=86400                                           # Set the DNS TTL (seconds) Default: 24h (Max for Cloudflare)

###########################################
## Check if we have a public IP
###########################################
echo "Checking for Public IP"

ipv4_regex='([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])'
ip=$(curl -s -4 https://cloudflare.com/cdn-cgi/trace | grep -E '^ip'); ret=$?
if [[ ! $ret -ne 0 ]]; then # In the case that cloudflare failed to return an ip.
    # Attempt to get the ip from other websites.
    ip=$(curl -s https://api.ipify.org || curl -s https://ipv4.icanhazip.com)
else
    # Extract just the ip from the ip line from cloudflare.
    ip=$(echo $ip | sed -E "s/^ip=($ipv4_regex)$/\1/")
fi

# Use regex to check for proper IPv4 format.
echo "$ip" | grep -E "^$ipv4_regex$" > /dev/null
if [ $? -ne 0 ]; then
    echo "DDNS Updater: Failed to find a valid IP."  >&2
    exit 2
fi

echo "Checked for Public IP: $ip"

###########################################
## Check and set the proper auth header
###########################################
echo "Checking and setting Auth Header"
if [[ "${auth_method}" = "global" ]]; then
  auth_header="X-Auth-Key:"
else
  auth_header="Authorization: Bearer"
fi

echo "Checked Auth Header: $auth_header"

###########################################
## Seek for the A record
###########################################
echo "Looking for A Record"

echo "DDNS Updater: Check Initiated"  >&2
record=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?type=A&name=$record_name" \
                      -H "X-Auth-Email: $auth_email" \
                      -H "$auth_header $auth_key" \
                      -H "Content-Type: application/json")

###########################################
## Check if the domain has an A record
###########################################
if [[ $record = *"\"count\":0"* ]]; then
  echo "DDNS Updater: Record does not exist, perhaps create one first? (${ip} for ${record_name})"  >&2
  exit 1
fi

echo "Found A Record: $record"

###########################################
## Get existing IP
###########################################
echo "Finding existing IP"

old_ip=$(echo "$record" | sed -E 's/.*"content":"(([0-9]{1,3}\.){3}[0-9]{1,3})".*/\1/')
# Compare if they're the same
if [[ $ip = $old_ip ]]; then
  echo "DDNS Updater: IP ($ip) for ${record_name} has not changed."  >&2
  exit 0
fi

echo "Found existing IP: $old_ip"

###########################################
## Set the record identifier from result
###########################################
echo "Setting record ID from result..."

record_identifier=$(echo "$record" | sed -E 's/.*"id":"([A-Za-z0-9_]+)".*/\1/')

echo "Set record ID"

###########################################
## Change the IP@Cloudflare using the API
###########################################
echo "Updating Cloudflare IP"

# Prepare JSON payload
json_payload="{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":$ttl,\"proxied\":true}"
echo "JSON Payload: $json_payload"  # Debugging line

update=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" \
                     -H "X-Auth-Email: $auth_email" \
                     -H "$auth_header $auth_key" \
                     -H "Content-Type: application/json" \
                     --data "$json_payload")

# Print the update response for debugging
echo "Update response: $update"

# Check if the response indicates success
if [[ $update == *"\"success\":false"* ]]; then
    echo "DDNS Updater: Failed to update the IP address. Response: $update" >&2
    exit 1
fi

echo "DDNS Updater: IP address updated successfully. Response: $update"
