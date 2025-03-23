#!/bin/bash
# -- version 1.0 hookprobe.com --- Ubuntu 24.10
set -e

# --- Create an APP NAME Bridge & app for your application --- #PSQL_KEY = 4bit , NETWORK_NAME = should be none to use nsenter. custom build to use NAT and PAT for security increase
APP_NAME="your_app"
NETWORK_NAME="none" 

# --- alocate IP variables for OpenVirtual Switch & IP vor vxlan
VXLAN_IP=192.168.0.1
PSQL_KEY=1111
APP_PSK="password_for_vxlan"
PSQL_OVS=psql-ovs
PSQL_NETNS=psql-netns
DJANGO_OVS=django-ovs
DJANGO_NETNS=django-netns
NGINX_OVS=nginx-ovs
NGINX_NETNS=nginx-netns
CFL_OVS=cfl-ovs
CFL_NETNS=cfl-netns

# --- alocate IP variables for all Containers
CT_DEF_GW=10.20.30.1
PSQL_IP=10.20.30.255
DJANGO_IP=10.20.30.254
NGINX_IP=10.20.30.253
CFL_IP=10.20.30.252

# --- Container Names variables

DB_CONTAINER_NAME="your_app_psql"
DJANGO_CT_NAME="django"
NGINX_CT_NAME="nginx"
CLOUDFLARED_CT_NAME="cloudflared"

# --- Database Variabales for PSQL Container
DB_USER="your_user"
DB_PASSWORD="your_secret_password"
DB_NAME="database"
DB_APP=your_DB_volume
