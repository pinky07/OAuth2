#!/bin/sh
#

IMAGE_NAME='com.gft.oauth2:latest'
echo 'Launching new container based on image' $IMAGE_NAME

CONTAINER_ID=`docker run -e 'SPRING_PROFILES_ACTIVE=default,dev' -d -p 11003:11003 $IMAGE_NAME`
echo 'Created container with ID' $CONTAINER_ID

echo 'Waiting 30s'
sleep 30s

docker logs $CONTAINER_ID

echo 'Success'