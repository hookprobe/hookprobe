#!/bin/bash

source network-config.sh

#Flush all created components
echo "Flushing existing setup from system"

podman container stop ${DB_CONTAINER_NAME}
podman container rm ${DB_CONTAINER_NAME}

podman container stop ${DJANGO_CT_NAME}
podman container rm ${DJANGO_CT_NAME}

podman container stop ${NGINX_CT_NAME}
podman container rm ${NGINX_CT_NAME}

podman container stop ${CLOUDFLARED_CT_NAME}
podman container rm ${CLOUDFLARED_CT_NAME}

sudo ip addr flush dev ${APP_NAME}
sudo ip addr flush dev app-gatewayhost

sudo ovs-vsctl del-br ${APP_NAME}
sudo ip netns delete ${APP_NAME}
podman volume rm ${DB_APP} 
podman app rm ${APP_NAME}

sudo ip link delete dev app-gatewayhost
sudo ip link delete dev app-gatewayovs
rm -r web_app
rm -r nginx_conf
rm -r cloudflared

echo "Flush Complete...."
