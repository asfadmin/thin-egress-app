#! /usr/bash


function GENERATE_JWTKEYS_FILE {
    cat >  /tmp/jwtkeys.json <<EOL
{
    "rsa_priv_key": "${rsa_priv_key}",
    "rsa_pub_key":  "${rsa_pub_key}"
}

EOL

}

function GENERATE_TEA_CREDS {
  cd /tmp || exit 1
  ssh-keygen -t rsa -b 4096 -m PEM -f ./jwtcookie.key -N ''
  openssl base64 -in jwtcookie.key -out jwtcookie.key.b64 -A
  openssl base64 -in jwtcookie.key.pub -out jwtcookie.key.pub.b64 -A

  export rsa_priv_key=$(<jwtcookie.key.b64)
  export rsa_pub_key=$(<jwtcookie.key.pub.b64)
  rm jwtcookie.key*
  GENERATE_JWTKEYS_FILE
}

GENERATE_TEA_CREDS
aws secretsmanager create-secret --name jwt_secret_for_tea --profile ${profile_name:-default} --region ${aws_region:-us-west-2} \
    --description "RS256 keys for TEA app JWT cookies" \
    --secret-string file:///tmp/jwtkeys.json




