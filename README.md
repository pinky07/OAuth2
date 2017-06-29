
# OAuth2 Authorization Server

This microservice runs an OAuth2 authorization server.

Remember that since tokens are exposed to the network, they must be transported securely through HTTPS.

## Introduction

Read the following materials to get an introduction of how OAuth2 works:

1. From Digital Ocean: https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2

## URLs

If you want to test with Postman, you can use the following data:

1. Callback URL: <Set by Postman>
2. Token Name: <Set by you, any name is Ok>
3. Auth(orization) URL: http://localhost:11001/uaa/oauth/authorize <---> http://localhost:8888/uaa/oauth/authorize
4. Access Token URL: http://localhost:11001/uaa/oauth/authorize <---> http://localhost:8888/uaa/oauth/authorize
5. Client ID: app
6. Client secret: app-secret-password (doesn't make much sense because we're using a SPA so it's sort of public)
7. Scope: <TBD>
8. Grant Type: Authorization Code

## How to get a new certificate?

1. Install Docker and run the terminal for the following image (*Optional*). Alternatively you can try to run the commands directly in your OS (if not Windows).

	docker run -ti -v ~/tmp:/data java:8

2. Generate the certificate. Change the dname and password if necessary.

	keytool -genkeypair -alias jwt -keyalg RSA -dname "CN=jwt, OU=Internal Projects, O=GFT, L=La Aurora, S=Heredia, C=CR" -keypass mySecretKey -keystore /data/jwt.jks -storepass mySecretKey && echo "mySecretKey" | keytool -list -rfc --keystore /data/jwt.jks | openssl x509 -inform pem -pubkey > /data/public-key.pem 
	
## Should CSRF 
