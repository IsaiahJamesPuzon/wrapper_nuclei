#!/usr/bin/env python3
"""
nmap2nuclei.py - Automated Nuclei Scanner with Nmap Integration

Parses nmap scan results and executes targeted nuclei scans with specific templates.
Supports three detection strategies per port:
- Network-only: Pure protocol detection (FTP, SSH, etc.)
- HTTP-only: Web service detection
- Both: Try both network AND HTTP (for ambiguous ports like 9100)
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from uuid_utils import uuid7

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# Auto-detection removed - rely on nuclei binary to manage its own templates


@dataclass
class ServiceInfo:
    """Represents a detected network service"""
    host: str
    port: int
    protocol: str
    service: str
    version: str = ""
    product: str = ""
    state: str = "open"
    mac: str = None
    hostname: str = None
    os: str = None  # OS detection from nmap


@dataclass
class OSInfo:
    """Represents OS detection information"""
    host: str
    os_match: str = ""
    accuracy: int = 0


class ServiceMapper:
    """Maps nmap services and ports to specific nuclei template files"""
    
    # Port detection strategy:
    # - 'network': Network-level protocol detection templates (no HTTP attempt)
    # - 'http': HTTP-specific detection templates (will add generic HTTP templates too)
    # - 'both': Run BOTH network AND HTTP templates (for ambiguous ports)
    
    PORT_TEMPLATES = {
        # ============================================================
        # NETWORK-ONLY DETECTION (non-HTTP protocols)
        # ============================================================
        
        # Network Services - Authentication & Remote Access
        21: {
            'type': 'network',
            'templates': ['network/detection/ftp-detect.yaml']
        },
        22: {
            'type': 'network',
            'templates': ['network/detection/openssh-detect.yaml']
        },
        23: {
            'type': 'network',
            'templates': ['network/detection/telnet-detect.yaml']
        },
        3389: {
            'type': 'network',
            'templates': ['network/detection/rdp-detection.yaml']
        },
        5900: {
            'type': 'network',
            'templates': ['network/detection/vnc-service-detect.yaml']
        },
        5901: {
            'type': 'network',
            'templates': ['network/detection/vnc-service-detect.yaml']
        },
        5902: {
            'type': 'network',
            'templates': ['network/detection/vnc-service-detect.yaml']
        },
        5931: {
            'type': 'network',
            'templates': ['network/detection/vnc-service-detect.yaml']
        },
        
        # Network Services - Email
        25: {
            'type': 'network',
            'templates': ['network/detection/smtp-detect.yaml']
        },
        110: {
            'type': 'network',
            'templates': ['network/detection/pop3-detect.yaml']
        },
        143: {
            'type': 'network',
            'templates': ['network/detection/imap-detect.yaml']
        },
        465: {
            'type': 'network',
            'templates': ['network/detection/smtp-detect.yaml']
        },
        587: {
            'type': 'network',
            'templates': ['network/detection/smtp-detect.yaml']
        },
        2525: {
            'type': 'network',
            'templates': ['network/detection/smtp-detect.yaml']
        },
        
        # Network Services - Databases
        3306: {
            'type': 'network',
            'templates': [
                'network/detection/mysql-detect.yaml',
                'network/misconfig/mysql-native-password.yaml'
            ]
        },
        5432: {
            'type': 'network',
            'templates': [
                'network/detection/pgsql-detect.yaml',
                'network/misconfig/unauth-psql.yaml'
            ]
        },
        6379: {
            'type': 'network',
            'templates': [
                'network/detection/redis-detect.yaml',
                'network/exposures/exposed-redis.yaml',
                'javascript/default-logins/redis-default-logins.yaml'
            ]
        },
        6380: {
            'type': 'network',
            'templates': [
                'network/detection/redis-detect.yaml',
                'network/exposures/exposed-redis.yaml'
            ]
        },
        27017: {
            'type': 'network',
            'templates': [
                'network/detection/mongodb-detect.yaml',
                'network/misconfig/mongodb-unauth.yaml'
            ]
        },
        
        # Network Services - File Sharing & Other
        445: {
            'type': 'network',
            'templates': [
                'javascript/enumeration/smb/smb-version-detect.yaml',
                'network/honeypot/dionaea-smb-honeypot-detect.yaml'
            ]
        },
        548: {
            'type': 'network',
            'templates': ['network/detection/afp-server-detect.yaml']
        },
        1099: {
            'type': 'network',
            'templates': ['network/detection/java-rmi-detect.yaml']
        },
        2049: {
            'type': 'network',
            'templates': ['network/detection/nfs-v3-exposed.yaml']
        },
        4369: {
            'type': 'network',
            'templates': ['network/misconfig/erlang-daemon.yaml']
        },
        5037: {
            'type': 'network',
            'templates': ['network/exposures/exposed-adb.yaml']
        },
        
        # Distributed Systems & Message Queues
        2181: {
            'type': 'network',
            'templates': ['network/exposures/exposed-zookeeper.yaml']
        },
        2888: {
            'type': 'network',
            'templates': ['network/exposures/exposed-zookeeper.yaml']
        },
        3888: {
            'type': 'network',
            'templates': ['network/exposures/exposed-zookeeper.yaml']
        },
        5672: {
            'type': 'network',
            'templates': ['network/detection/rabbitmq-detect.yaml']
        },
        9092: {
            'type': 'network',
            'templates': ['network/enumeration/kafka-topics-list.yaml']
        },
        25672: {
            'type': 'network',
            'templates': ['network/detection/rabbitmq-detect.yaml']
        },
        
        # DNS Services (standard DNS and mDNS/Bonjour)
        53: {
            'type': 'network',
            'templates': ['dns/dns-waf-detect.yaml']
        },
        5353: {
            'type': 'network',
            'templates': ['dns/dns-waf-detect.yaml']  # mDNS (multicast DNS/Bonjour)
        },
        
        # ============================================================
        # HTTP-ONLY DETECTION (web services)
        # ============================================================
        
        3000: {
            'type': 'http',
            'templates': ['http/exposed-panels/grafana-detect.yaml']
        },
        4343: {
            'type': 'http',
            'templates': ['http/default-logins/others/aruba-instant-default-login.yaml']
        },
        5601: {
            'type': 'http',
            'templates': ['http/exposed-panels/kibana-detect.yaml']
        },
        8080: {
            'type': 'http',
            'templates': [
                'http/technologies/apache/tomcat-detect.yaml',
                'http/exposed-panels/jenkins-login.yaml'
            ]
        },
        8086: {
            'type': 'http',
            'templates': ['http/exposed-panels/influxdb-panel.yaml']
        },
        8123: {
            'type': 'http',
            'templates': ['http/misconfiguration/clickhouse-unauth-api.yaml']
        },
        9090: {
            'type': 'http',
            'templates': [
                'http/exposed-panels/prometheus-panel.yaml',
                'http/misconfiguration/prometheus/prometheus-unauth.yaml'
            ]
        },
        9091: {
            'type': 'http',
            'templates': ['http/exposed-panels/prometheus-panel.yaml']
        },
        9115: {
            'type': 'http',
            'templates': ['http/misconfiguration/prometheus/prometheus-exporter.yaml']
        },
        9200: {
            'type': 'http',
            'templates': ['http/misconfiguration/elasticsearch.yaml']
        },
        9300: {
            'type': 'http',
            'templates': ['http/misconfiguration/elasticsearch.yaml']
        },
        10050: {
            'type': 'http',
            'templates': ['http/exposed-panels/zabbix-server-login.yaml']
        },
        11434: {
            'type': 'http',
            'templates': [
                'http/exposed-panels/ollama-llm-panel.yaml',
                'http/misconfiguration/ollama-improper-authorization.yaml'
            ]
        },
        15672: {
            'type': 'http',
            'templates': ['http/exposed-panels/rabbitmq-detect.yaml']
        },
        
        # ============================================================
        # BOTH NETWORK AND HTTP DETECTION (ambiguous ports)
        # These ports will be scanned TWICE: once as network, once as HTTP
        # ============================================================
        
        # Port 9100: Could be HP JetDirect printer OR Prometheus exporter
        9100: {
            'type': 'both',
            'network_templates': ['network/misconfig/printers-info-leak.yaml'],
            'http_templates': ['http/misconfiguration/prometheus/prometheus-exporter.yaml']
        },
        
        # Port 7000: Could be RTSP (network) OR HTTP service
        7000: {
            'type': 'both',
            'network_templates': ['network/detection/rtsp-detect.yaml'],
            'http_templates': []  # Will get generic HTTP templates
        },
        
        # Container & Orchestration - Docker API (can be HTTP or socket)
        2375: {
            'type': 'both',
            'network_templates': ['network/exposures/exposed-dockerd.yaml'],
            'http_templates': ['http/misconfiguration/misconfigured-docker.yaml']
        },
        2376: {
            'type': 'both',
            'network_templates': ['network/exposures/exposed-dockerd.yaml'],
            'http_templates': ['http/misconfiguration/misconfigured-docker.yaml']
        },
        
        # Kubernetes API (primarily HTTP but can have network probes)
        6443: {
            'type': 'both',
            'network_templates': [],
            'http_templates': ['http/technologies/kubernetes/kube-api/kube-api-version.yaml']
        },
    }
    
    # Service/product to specific template files mapping
    TEMPLATES = {
        # HTTP Services - Generic & Web Servers
        'http': [
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
            'http/exposures/logs/git-exposure.yaml',  # Check for exposed .git on all HTTP services
        ],
        'https': [
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
            'http/exposures/logs/git-exposure.yaml',
        ],
        'http-proxy': [
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
        ],
        'apache': [
            'http/technologies/apache/apache-detect.yaml',
            'http/technologies/apache/default-apache2-page.yaml',
        ],
        'nginx': [
            'http/technologies/nginx/nginx-version.yaml',
            'http/technologies/nginx/default-nginx-page.yaml',
            'http/misconfiguration/nginx/nginx-status.yaml',
        ],
        'iis': [
            'http/technologies/microsoft/iis-detect.yaml',
        ],
        
        # HTTP Services - Application Servers
        'tomcat': [
            'http/technologies/apache/tomcat-detect.yaml',
            'http/exposed-panels/tomcat/tomcat-exposed.yaml',
        ],
        'jboss': ['http/technologies/jboss-detect.yaml'],
        'weblogic': [
            'http/exposed-panels/oracle-weblogic-console.yaml',
            'network/detection/weblogic-t3-detect.yaml',
            'network/detection/weblogic-iiop-detect.yaml',
        ],
        'websphere': ['http/technologies/ibm-websphere-detect.yaml'],
        
        # HTTP Services - CI/CD & DevOps
        'jenkins': [
            'http/technologies/jenkins-detect.yaml',
            'http/exposed-panels/jenkins-login.yaml',
        ],
        'gitlab': ['http/exposed-panels/gitlab-detect.yaml'],
        'gitea': ['http/technologies/gitea-detect.yaml'],
        'github': ['http/technologies/github-enterprise-detect.yaml'],
        'airflow': [
            'http/technologies/apache/airflow-detect.yaml',
            'http/exposed-panels/airflow-panel.yaml',
        ],
        'travis': ['http/technologies/travis-ci-detect.yaml'],
        'drone': ['http/exposed-panels/drone-ci-panel.yaml'],
        'concourse': ['http/exposed-panels/concourse-ci-panel.yaml'],
        'argo': ['http/exposed-panels/argocd-login.yaml'],
        'argocd': ['http/exposed-panels/argocd-login.yaml'],
        
        # HTTP Services - CMS & Frameworks
        'wordpress': [
            'http/technologies/wordpress-detect.yaml',
            'http/exposed-panels/wordpress-login.yaml',
        ],
        'joomla': ['http/technologies/joomla-detect.yaml'],
        'drupal': ['http/technologies/drupal-detect.yaml'],
        'magento': ['http/technologies/magento-detect.yaml'],
        'sharepoint': ['http/technologies/microsoft/sharepoint-detect.yaml'],
        
        # HTTP Services - Monitoring & Observability
        'grafana': [
            'http/exposed-panels/grafana-detect.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        'prometheus': [
            'http/exposed-panels/prometheus-panel.yaml',
            'http/misconfiguration/prometheus/prometheus-unauth.yaml',
        ],
        'kibana': [
            'http/exposed-panels/kibana-detect.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        'nagios': ['http/exposed-panels/nagios-panel.yaml'],
        'zabbix': [
            'http/exposed-panels/zabbix-detect.yaml',
            'http/exposed-panels/zabbix-server-login.yaml',
        ],
        'influxdb': ['http/exposed-panels/influxdb-panel.yaml'],
        'jaeger': ['http/technologies/tech-detect.yaml'],
        'zipkin': ['http/technologies/tech-detect.yaml'],
        'logstash': ['http/technologies/tech-detect.yaml'],
        'loki': ['http/technologies/tech-detect.yaml'],
        
        # HTTP Services - Collaboration & Project Management
        'jira': ['http/technologies/jira-detect.yaml'],
        'confluence': ['http/technologies/confluence-detect.yaml'],
        'redmine': ['http/technologies/redmine-detect.yaml'],
        'mattermost': ['http/exposed-panels/mattermost-detect.yaml'],
        'rocketchat': ['http/technologies/rocketchat-detect.yaml'],
        
        # HTTP Services - Databases & Admin Panels
        'phpmyadmin': [
            'http/exposed-panels/phpmyadmin-panel.yaml',
            'http/misconfiguration/phpmyadmin/phpmyadmin-misconfiguration.yaml',
            'http/misconfiguration/phpmyadmin/phpmyadmin-setup.yaml',
        ],
        'adminer': ['http/exposed-panels/adminer-panel.yaml'],
        'pgadmin': ['http/exposed-panels/phppgadmin-panel.yaml'],
        'mongodb-express': ['http/technologies/mongoose-server.yaml'],
        'elasticsearch': [
            'http/misconfiguration/elasticsearch.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        'couchdb': [
            'http/exposed-panels/couchdb-exposure.yaml',
            'http/exposed-panels/couchdb-fauxton.yaml',
        ],
        'arangodb': ['http/exposed-panels/arangodb-web-Interface.yaml'],
        'influxdb': ['http/exposed-panels/influxdb-panel.yaml'],
        
        # HTTP Services - Infrastructure & Container Management
        'docker-registry': ['http/technologies/docker-registry-browser-detect.yaml'],
        'kubernetes-dashboard': ['http/technologies/kubernetes-operational-view-detect.yaml'],
        'rancher': ['http/exposed-panels/rancher-panel.yaml'],
        'portainer': ['http/exposed-panels/portainer-panel.yaml'],
        'traefik': [
            'http/exposed-panels/traefik-dashboard.yaml',
            'http/exposures/apis/traefik-api-enabled.yaml',
        ],
        'kubernetes': [
            'http/technologies/kubernetes/kube-api/kube-api-version.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        
        # HTTP Services - AI/ML & LLM Services
        'ollama': [
            'http/exposed-panels/ollama-llm-panel.yaml',
            'http/misconfiguration/ollama-improper-authorization.yaml',
        ],
        'vllm': [
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
        ],
        
        # HTTP Services - Network Equipment
        'mikrotik': [
            'http/exposed-panels/mikrotik/mikrotik-routeros.yaml',
            'http/technologies/mikrotik-httpproxy.yaml',
            'network/detection/mikrotik-routeros-api.yaml',
        ],
        'ubiquiti': ['http/exposed-panels/ubiquiti-unifi.yaml'],
        'pfsense': ['http/exposed-panels/pfsense-detect.yaml'],
        'opnsense': ['http/exposed-panels/opnsense-login.yaml'],
        'aruba': [
            'http/default-logins/others/aruba-instant-default-login.yaml',
            'http/exposed-panels/hpe-system-management-login.yaml',
        ],
        'hpe': [
            'http/exposed-panels/hpe-system-management-login.yaml',
            'http/misconfiguration/hpe-system-management-anonymous.yaml',
        ],
        'mini_httpd': [
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
        ],
        
        # Printer Services (HP, Canon, Epson, Brother, Fuji Xerox)
        'soap': [
            'http/iot/hp-laserjet-detect.yaml',
            'http/iot/hp-color-laserjet-detect.yaml',
            'http/iot/hp-device-info-detect.yaml',
            'http/misconfiguration/hp/unauthorized-hp-printer.yaml',
            'http/misconfiguration/hp/unauthorized-printer-hp.yaml',
            'http/default-logins/hp/hp-printer-default-login.yaml',
            'http/default-logins/hp/hp-switch-default-login.yaml',
        ],
        'jetdirect': [
            'network/misconfig/printers-info-leak.yaml',
        ],
        'gsoap': [
            'http/iot/hp-laserjet-detect.yaml',
            'http/iot/hp-color-laserjet-detect.yaml',
            'http/iot/hp-device-info-detect.yaml',
        ],
        'printer': [
            'http/iot/hp-laserjet-detect.yaml',
            'http/iot/hp-device-info-detect.yaml',
            'http/misconfiguration/hp/unauthorized-hp-printer.yaml',
            'http/technologies/hp-blade-admin-detect.yaml',
            'http/exposed-panels/brother-printer-panel.yaml',
            'http/exposed-panels/epson-access-detect.yaml',
            'http/exposed-panels/fuji-xerox-printer-detect.yaml',
        ],
        'canon': [
            'http/misconfiguration/canon-c3325-unauth.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        'hp': [
            'http/technologies/hp-blade-admin-detect.yaml',
            'http/misconfiguration/hp/unauthorized-hp-printer.yaml',
            'http/default-logins/hp/hp-printer-default-login.yaml',
            'http/exposed-panels/hpe-system-management-login.yaml',
        ],
        'brother': [
            'http/exposed-panels/brother-printer-panel.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        'epson': [
            'http/exposed-panels/epson-access-detect.yaml',
            'http/exposed-panels/epson-web-control-detect.yaml',
            'http/exposed-panels/epson-projector-detect.yaml',
        ],
        
        # Network Services - Authentication & Remote Access
        'ssh': ['network/detection/openssh-detect.yaml'],
        'ftp': ['network/detection/ftp-detect.yaml'],
        'rdp': ['network/detection/rdp-detection.yaml'],
        'vnc': ['network/detection/vnc-service-detect.yaml'],
        'telnet': ['network/detection/telnet-detect.yaml'],
        
        # Network Services - Databases
        'mysql': [
            'network/detection/mysql-detect.yaml',
            'network/misconfig/mysql-native-password.yaml',
        ],
        'mariadb': [
            'network/detection/mysql-detect.yaml',
            'network/misconfig/mysql-native-password.yaml',
        ],
        'postgresql': [
            'network/detection/pgsql-detect.yaml',
            'network/misconfig/unauth-psql.yaml',
        ],
        'postgres': [
            'network/detection/pgsql-detect.yaml',
            'network/misconfig/unauth-psql.yaml',
        ],
        'redis': [
            'network/detection/redis-detect.yaml',
            'network/exposures/exposed-redis.yaml',
            'javascript/default-logins/redis-default-logins.yaml',
        ],
        'mongodb': [
            'network/detection/mongodb-detect.yaml',
            'network/misconfig/mongodb-unauth.yaml',
        ],
        'mongod': [
            'network/detection/mongodb-detect.yaml',
            'network/misconfig/mongodb-unauth.yaml',
        ],
        'memcached': ['network/misconfig/memcached-stats.yaml'],
        'clickhouse': [
            'network/misconfig/clickhouse-unauth.yaml',
            'http/misconfiguration/clickhouse-unauth-api.yaml',
        ],
        'cassandra': ['network/detection/cql-native-transport.yaml'],
        'cql': ['network/detection/cql-native-transport.yaml'],
        'couchdb': [
            'http/exposed-panels/couchdb-exposure.yaml',
            'http/exposed-panels/couchdb-fauxton.yaml',
        ],
        'riak': ['network/detection/riak-detect.yaml'],
        
        # Network Services - Message Queues & Distributed Systems
        'amqp': [
            'network/detection/rabbitmq-detect.yaml',
            'http/exposed-panels/rabbitmq-detect.yaml',
        ],
        'rabbitmq': [
            'network/detection/rabbitmq-detect.yaml',
            'http/exposed-panels/rabbitmq-detect.yaml',
        ],
        'zookeeper': ['network/exposures/exposed-zookeeper.yaml'],
        'eforward': ['network/exposures/exposed-zookeeper.yaml'],  # ZooKeeper typically on this port
        'kafka': [
            'network/enumeration/kafka-topics-list.yaml',
            'http/technologies/tech-detect.yaml',
        ],
        'activemq': [
            'network/detection/apache-activemq-detect.yaml',
            'network/detection/activemq-openwire-transport-detect.yaml',
            'http/exposed-panels/activemq-panel.yaml',
        ],
        'rocketmq': ['network/misconfig/apache-rocketmq-broker-unauth.yaml'],
        'dubbo': ['network/misconfig/apache-dubbo-unauth.yaml'],
        
        # Network Services - Container & Orchestration
        'docker': ['network/exposures/exposed-dockerd.yaml'],
        'kubernetes': ['http/technologies/kubernetes/kube-api/kube-api-version.yaml'],
        
        # Network Services - Monitoring & Management
        'snmp': ['network/detection/snmp-detect.yaml'],
        'ldap': ['network/detection/ldap-detect.yaml'],
        # DNS service - Note: Most Nuclei DNS templates are for domain queries (SPF, DMARC, etc.)
        # but we'll try anyway in case some work for service detection
        'dnsmasq': ['dns/dns-waf-detect.yaml'],  # DNS/DHCP server
        'domain': ['dns/dns-waf-detect.yaml'],  # DNS service

        # Network Services - File Sharing
        'smb': ['network/honeypot/dionaea-smb-honeypot-detect.yaml'],
        'microsoft-ds': ['network/honeypot/dionaea-smb-honeypot-detect.yaml'],
        'nfs': ['network/detection/nfs-detect.yaml'],
        
        # Network Services - Email
        'smtp': ['network/detection/smtp-detect.yaml'],
        'imap': ['network/detection/imap-detect.yaml'],
        'pop3': ['network/detection/pop3-detect.yaml'],
        
        # Network Services - Streaming & Media
        'rtsp': ['network/detection/rtsp-detect.yaml'],
        
        # Network Services - Other
        'epmd': ['network/misconfig/erlang-daemon.yaml'],  # Erlang Port Mapper
        'clamav': [
            'network/misconfig/clamav-unauth.yaml',
            'network/detection/clamav-detect.yaml',
        ],
        'rpcbind': ['network/detection/rpcbind-portmapper-detect.yaml'],
        'rpc': ['network/detection/rpcbind-portmapper-detect.yaml'],
        'rsync': ['network/detection/rsyncd-service-detect.yaml'],
        'rsyncd': ['network/detection/rsyncd-service-detect.yaml'],
        'jdwp': ['network/detection/jdwp-detect.yaml'],
        'xmpp': ['network/detection/detect-jabber-xmpp.yaml'],
        'jabber': ['network/detection/detect-jabber-xmpp.yaml'],
        
        # Network Services - Generic Protocol Detection
        # These are for services detected by nmap but without specific templates
        'tcpwrapped': [],  # Wrapped services - no point in scanning
        'unknown': [],  # Unknown services - no templates available
        
        # Services that should be treated as HTTP but have non-standard names
        'cslistener': [  # Often used for various listeners, treat as HTTP
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
        ],
        'https-alt': [  # Alternative HTTPS port
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
        ],
        'ssl': [  # Generic SSL/TLS service
            'http/technologies/tech-detect.yaml',
            'http/technologies/default-detect-generic.yaml',
        ],
        
        # IoT & Camera Devices
        'hikvision': [
            'http/technologies/hikvision-detect.yaml',
            'http/iot/hikvision-cam-info-exposure.yaml',
            'http/exposures/configs/hikvision-info-leak.yaml',
            'http/misconfiguration/hikvision-env.yaml',
            'http/cves/2021/CVE-2021-36260.yaml',  # Critical RCE
            'http/cves/2017/CVE-2017-7921.yaml',   # Authentication bypass
        ],
        'hik-connect': [  # HikVision camera control service
            'http/technologies/hikvision-detect.yaml',
            'http/iot/hikvision-cam-info-exposure.yaml',
            'http/exposures/configs/hikvision-info-leak.yaml',
            'http/misconfiguration/hikvision-env.yaml',
            'http/cves/2021/CVE-2021-36260.yaml',
            'http/cves/2017/CVE-2017-7921.yaml',
        ],
    }
    
    # Comprehensive list of HTTP/HTTPS ports for generic web scanning
    # Includes common development servers, CI/CD, monitoring, and service ports
    # NOTE: Port 9100 removed from HTTP_PORTS - it will be tested as BOTH network and HTTP
    HTTP_PORTS = {
        # Standard HTTP/HTTPS
        80, 443, 8080, 8443, 8081, 8082, 8083, 8090, 8095, 8888,
        
        # Development & Testing Tools
        3000,    # Grafana, Node.js dev servers, React dev servers
        3001, 3002, 3003, 3100,  # Alternative dev ports, Loki
        4200,    # Angular dev server
        4343,    # Aruba Instant On
        5000, 5001, 5002, 5004, 5006, 5007, 5008,  # Flask, various dev servers
        5173,    # Vite dev server
        5555, 5559,  # Postman proxy
        5678, 5679,  # n8n workflow automation
        6000, 6001, 6002,  # Firefox debugger, X11
        7000, 7070,  # Various services (7000 is ambiguous - RTSP or HTTP)
        8000,    # vLLM, Python HTTP servers, Django dev
        8001, 8002, 8003, 8004, 8005,  # Alternative dev ports
        8086,    # InfluxDB
        8123,    # ClickHouse HTTP API
        9222,    # Chrome remote debugging
        9418,    # Git daemon
        11434,   # Ollama LLM API
        63342,   # JetBrains IDE built-in web server
        
        # CI/CD & DevOps
        50000,   # Jenkins inbound agent port
        
        # Monitoring & Observability
        3333,    # Grafana alternative
        5044,    # Logstash Beats input
        5601,    # Kibana
        9090, 9091,  # Prometheus
        9115,    # Prometheus exporters (9100 excluded - tested as BOTH)
        9200, 9300,  # Elasticsearch
        9411,    # Zipkin
        9600,    # Logstash monitoring
        14268,   # Jaeger HTTP collector
        16686,   # Jaeger UI
        
        # Message Queues & Distributed Systems
        15672,   # RabbitMQ management UI
        
        # Databases with HTTP interfaces
        5984,    # CouchDB
        7474,    # Neo4j Browser
        8529,    # ArangoDB
        9092,    # Kafka (some HTTP interfaces)
        
        # Infrastructure & Container Management
        2375, 2376,  # Docker API (also tested as network)
        6443,    # Kubernetes API (also tested as network)
        10050,   # Zabbix
        
        # Additional common ports
        2000, 2233, 2267, 3339, 3341, 4306, 4848, 5500, 5700, 5701, 5731, 5732,
        7698, 8844, 8892, 8893, 9000, 9002, 9003, 9004, 9005, 9006, 9007, 9210,
        9306, 9312, 9314, 9315, 9320, 9510, 9922, 9923, 10661, 12438, 15495,
        17281, 17690, 18832, 20437, 20584, 20850, 21326, 22000, 25007, 25725,
        26218, 26661, 33795, 40004, 50001, 50002, 50003, 50004, 50005, 50009,
        50011, 50017, 50020, 50022, 60000, 60001, 60002, 60003, 60004, 60005,
        60008, 60009, 60011
    }
    
    @classmethod
    def get_templates_for_port(cls, service: str, product: str, port: int) -> List[Tuple[str, List[str]]]:
        """
        Get nuclei template files for a service/port combination.
        Returns list of tuples: [(scan_type, [templates]), ...]
        scan_type can be 'network' or 'http'
        """
        results = []
        
        # Check if port has specific configuration
        if port and port in cls.PORT_TEMPLATES:
            port_config = cls.PORT_TEMPLATES[port]
            detection_type = port_config['type']
            
            if detection_type == 'network':
                # Network-only detection
                return [('network', port_config['templates'])]
            
            elif detection_type == 'http':
                # HTTP-only detection - merge with generic HTTP templates
                templates = port_config['templates'].copy()
                for template in cls.TEMPLATES['http']:
                    if template not in templates:
                        templates.append(template)
                return [('http', templates)]
            
            elif detection_type == 'both':
                # Both network AND HTTP detection
                # Add network scan
                if port_config.get('network_templates'):
                    results.append(('network', port_config['network_templates']))
                
                # Add HTTP scan with generic HTTP templates merged
                http_templates = port_config.get('http_templates', []).copy()
                for template in cls.TEMPLATES['http']:
                    if template not in http_templates:
                        http_templates.append(template)
                results.append(('http', http_templates))
                
                return results
        
        # No port-specific config, check service/product name matching
        for key in [product.lower(), service.lower()]:
            if not key:
                continue
            # Direct match
            if key in cls.TEMPLATES:
                templates = cls.TEMPLATES[key]
                # Determine if it's HTTP or network based on template paths
                if templates and any('http/' in t for t in templates):
                    return [('http', templates)]
                else:
                    return [('network', templates)]
            # Partial match (longest keys first to avoid false matches)
            for template_key in sorted(cls.TEMPLATES.keys(), key=len, reverse=True):
                if template_key in key:
                    templates = cls.TEMPLATES[template_key]
                    if templates and any('http/' in t for t in templates):
                        return [('http', templates)]
                    else:
                        return [('network', templates)]
        
        # Check if port is a known HTTP port (generic HTTP detection fallback)
        if port and port in cls.HTTP_PORTS:
            return [('http', cls.TEMPLATES['http'].copy())]
        
        # Fallback for HTTP-like service names
        if any(x in service.lower() for x in ['http', 'www', 'web']):
            return [('http', cls.TEMPLATES['http'])]
        
        return []
    
    @classmethod
    def is_http_service(cls, service: str, port: int) -> bool:
        """Check if service is HTTP/HTTPS"""
        http_keywords = ['http', 'https', 'www', 'web', 'soap', 'ssl', 'tls']
        return port in cls.HTTP_PORTS or any(x in service.lower() for x in http_keywords)


class NmapParser:
    """Parse nmap scan results"""
    
    @staticmethod
    def parse_xml(filepath: str) -> Tuple[List[ServiceInfo], List[OSInfo]]:
        """Parse nmap XML format"""
        services, os_info_list = [], []
        
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                # Get host address
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                if addr_elem is None:
                    addr_elem = host.find('.//address[@addrtype="ipv6"]')
                if addr_elem is None:
                    continue
                host_addr = addr_elem.get('addr')
                
                # Extract MAC address
                mac_elem = host.find('.//address[@addrtype="mac"]')
                mac_addr = mac_elem.get('addr') if mac_elem is not None else None
                
                # Extract hostname
                hostname_elem = host.find('.//hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else None
                
                # Extract OS information
                os_name = None
                osmatch = host.find('.//os/osmatch')
                if osmatch is not None:
                    os_name = osmatch.get('name', '')
                    os_info_list.append(OSInfo(
                        host=host_addr,
                        os_match=os_name,
                        accuracy=int(osmatch.get('accuracy', 0))
                    ))
                
                # Extract open ports
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is None or state.get('state') != 'open':
                        continue
                    
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol')
                    service_elem = port.find('service')
                    
                    if service_elem is not None:
                        services.append(ServiceInfo(
                            host=host_addr,
                            port=port_num,
                            protocol=protocol,
                            service=service_elem.get('name', 'unknown'),
                            version=f"{service_elem.get('product', '')} {service_elem.get('version', '')}".strip(),
                            product=service_elem.get('product', ''),
                            state='open',
                            mac=mac_addr,
                            hostname=hostname,
                            os=os_name
                        ))
        except Exception as e:
            logger.error(f"Error parsing XML: {e}")
        
        return services, os_info_list
    
    @staticmethod
    def parse_gnmap(filepath: str) -> List[ServiceInfo]:
        """Parse nmap GNMAP format"""
        services = []
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    # Skip comments and empty lines
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    # GNMAP format: Host: <ip> (...) Ports: <port>/<state>/<protocol>/<owner>/<service>/<rpc>/<version>
                    if line.startswith('Host:') and 'Ports:' in line:
                        parts = line.split('\t')
                        host = parts[0].split()[1]
                        
                        # Find the Ports: section
                        ports_section = None
                        for part in parts:
                            if part.startswith('Ports:'):
                                ports_section = part.replace('Ports: ', '').strip()
                                break
                        
                        if not ports_section:
                            continue
                        
                        # Parse each port entry
                        port_entries = ports_section.split(', ')
                        for entry in port_entries:
                            fields = entry.split('/')
                            if len(fields) >= 7:
                                port_num = int(fields[0])
                                state = fields[1]
                                protocol = fields[2]
                                service_name = fields[4] if fields[4] else 'unknown'
                                version_info = fields[6] if len(fields) > 6 else ''
                                
                                if state == 'open':
                                    services.append(ServiceInfo(
                                        host=host,
                                        port=port_num,
                                        protocol=protocol,
                                        service=service_name,
                                        version=version_info,
                                        product='',
                                        state='open'
                                    ))
        except Exception as e:
            logger.error(f"Error parsing GNMAP: {e}")
        
        return services

def parse_open_ports_summary(filepath: str) -> List[ServiceInfo]:
    """Parse open_ports_summary.txt format (IP PORT1,PORT2,PORT3)"""
    services = []
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Format: IP PORT1,PORT2,PORT3
                parts = line.split()
                if len(parts) != 2:
                    continue
                
                host = parts[0]
                ports = parts[1].split(',')
                
                for port_str in ports:
                    try:
                        port = int(port_str.strip())
                        # Create minimal ServiceInfo - service detection will be port-based
                        services.append(ServiceInfo(
                            host=host,
                            port=port,
                            protocol='tcp',  # Assume TCP
                            service='unknown',  # Will rely on port-based detection
                            version='',
                            product='',
                            state='open'
                        ))
                    except ValueError:
                        logger.warning(f"Invalid port number: {port_str}")
                        continue
    except Exception as e:
        logger.error(f"Error parsing open ports summary: {e}")
    
    return services

def enrich_nuclei_finding(finding: Dict, service: ServiceInfo = None) -> Dict:
    """
    Enrich nuclei finding with metadata for CTEM ingestion.
    Adds resource information and data classification hints.
    Includes MAC address, hostname, and OS info from service if available.
    """
    from urllib.parse import urlparse
    from hashlib import sha256
    
    # Extract basic info
    matched_at = finding.get('matched-at', '')
    host = finding.get('host', '')
    template_id = finding.get('template-id', '')
    info = finding.get('info', {})
    tags = [tag.lower() for tag in info.get('tags', [])]
    finding_type = finding.get('type', 'unknown')
    
    # Determine resource type and identifier
    resource_type = None
    resource_identifier = None
    
    # Parse the matched-at or host to determine resource
    target_url = matched_at or host
    
    if any(x in target_url for x in ['http://', 'https://']):
        # HTTP/HTTPS resource
        try:
            parsed = urlparse(target_url)
            resource_identifier = parsed.path or '/'
            
            # Classify resource type based on path and tags
            path_lower = resource_identifier.lower()
            if any(x in path_lower for x in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '/api.', 'api/']):
                resource_type = 'api_endpoint'
            elif any(x in path_lower for x in ['.git', '/git/', '.svn', '/svn/']):
                resource_type = 'repo'
            else:
                resource_type = 'http_path'
        except:
            resource_type = 'http_path'
            resource_identifier = target_url
    
    # Network protocol resources
    elif finding_type in ['tcp', 'udp'] or any(x in tags for x in ['network', 'tcp', 'udp']):
        if 'smb' in tags or 'cifs' in tags or template_id.startswith('smb-'):
            resource_type = 'smb_share'
            resource_identifier = target_url
        elif 'nfs' in tags or 'nfs' in template_id:
            resource_type = 'nfs_export'
            resource_identifier = target_url
        elif 'mdns' in tags or 'bonjour' in tags:
            resource_type = 'mdns_service'
            resource_identifier = target_url
        # Default for other network protocols - no specific resource type
    
    elif finding_type == 'dns' or 'dns' in tags:
        resource_type = 'domain'
        resource_identifier = target_url
    
    # Classify data based on tags, template, and description
    data_classifications = []
    template_lower = template_id.lower()
    description = info.get('description', '').lower()
    name = info.get('name', '').lower()
    
    # Source code exposure
    if any(x in tags for x in ['git', 'svn', 'cvs', 'source', 'code', 'repo', 'vcs']) or \
    any(x in template_lower for x in ['git', 'svn', 'source', 'code', 'repo']) or \
    any(x in name for x in ['git', 'source code', 'repository']):
        data_classifications.append('source_code')
    
    # Secrets/API keys
    if any(x in tags for x in ['secret', 'token', 'api-key', 'apikey', 'key', 'keys']) or \
    any(x in template_lower for x in ['secret', 'token', 'api-key', 'apikey', '-key']) or \
    any(x in name for x in ['secret', 'token', 'api key', 'private key']):
        data_classifications.append('secrets')
    
    # Credentials
    if any(x in tags for x in ['credential', 'credentials', 'password', 'login', 'auth', 'default-login']) or \
    any(x in template_lower for x in ['credential', 'password', 'login', 'default-login', 'auth']) or \
    any(x in name for x in ['credential', 'password', 'default login', 'authentication']):
        data_classifications.append('credentials')
    
    # PII
    if any(x in tags for x in ['pii', 'personal', 'gdpr', 'privacy']) or \
    any(x in description for x in ['personal information', 'user data', 'pii']) or \
    any(x in name for x in ['personal', 'user data']):
        data_classifications.append('pii')
    
    # Internal-only data (generic exposure/leak without specific classification)
    if any(x in tags for x in ['exposure', 'disclosure', 'leak', 'exposed']) or \
    any(x in template_lower for x in ['exposure', 'disclosure', 'leak', 'exposed']):
        if not data_classifications:  # Only add if no other specific classification
            data_classifications.append('internal_only')
    
    # If no classification found, mark as unknown
    if not data_classifications:
        data_classifications.append('unknown')
    
    # Determine transport layer protocol
    # UDP services by port and protocol type
    UDP_PORTS = {53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900, 4500, 5353}
    
    # Extract port from target if available
    port_num = None
    if ':' in target_url and not target_url.startswith('http'):
        try:
            port_num = int(target_url.split(':')[-1].split('/')[0])
        except:
            pass
    
    # Determine transport
    transport = 'tcp'  # default
    if finding_type in ['dns', 'udp']:
        transport = 'udp'
    elif port_num and port_num in UDP_PORTS:
        transport = 'udp'
    elif 'udp' in ' '.join(tags):
        transport = 'udp'
    elif finding_type == 'icmp':
        transport = 'icmp'
    
    # Add enrichment metadata to finding
    finding['_ctem_enrichment'] = {
        'resource_type': resource_type,
        'resource_identifier': resource_identifier or matched_at or host,
        'data_classifications': list(set(data_classifications)),  # Remove duplicates
        'template_id': template_id,
        'template_name': info.get('name', template_id),
        'severity': info.get('severity', 'info'),
        'tags': tags,
        'description': info.get('description', ''),
        'cwe': info.get('classification', {}).get('cwe-id', []),
        'cvss': info.get('classification', {}).get('cvss-metrics', ''),
        'extracted_results': finding.get('extracted-results', []),
        'transport': transport,  # Transport layer protocol
        'mac': service.mac if service else None,
        'hostname': service.hostname if service else None,
        'os': service.os if service else None  # OS detection from nmap
    }
    
    return finding


class NucleiScanner:
    """Execute nuclei scans with specific templates"""
    
    def __init__(self, nuclei_path: str = "nuclei", rate_limit: int = 30, dry_run: bool = False, templates_dir: Optional[str] = None):
        self.nuclei_path = nuclei_path
        self.rate_limit = rate_limit
        self.dry_run = dry_run
        
        # Use templates_dir if explicitly provided, otherwise let nuclei use its default
        self.templates_dir = templates_dir
            
        if not dry_run:
            self._verify_nuclei()
    
    def _verify_nuclei(self):
        """Verify nuclei is installed"""
        try:
            result = subprocess.run([self.nuclei_path, '-version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"Nuclei found: {result.stdout.strip()}")
        except Exception as e:
            logger.error(f"Nuclei not found: {e}")
            sys.exit(1)
    
    def scan_services(self, services: List[ServiceInfo]) -> Tuple[List[Dict], List[str]]:
        """Scan all services (both HTTP and network)"""
        logger.info("Running nuclei scans...")
        
        all_findings = []
        templates_used = []
        
        for service in services:
            # Get templates for this service - may return multiple scan types
            scans = ServiceMapper.get_templates_for_port(service.service, service.product, service.port)
            
            if not scans:
                logger.info(f"⚠️  No templates found for {service.host}:{service.port}/{service.protocol} "
                           f"[service={service.service}, product={service.product}]")
                continue
            
            # Execute each scan type (network, http, or both)
            for scan_type, templates in scans:
                if not templates:
                    continue
                    
                # Build target based on scan type
                if scan_type == 'http':
                    protocol = 'https' if service.port == 443 or 'ssl' in service.service.lower() or service.port == 8443 else 'http'
                    target = f"{protocol}://{service.host}" if service.port in [80, 443] else f"{protocol}://{service.host}:{service.port}"
                else:  # network
                    target = f"{service.host}:{service.port}"
                
                # Execute scan
                scan_label = f"[{scan_type.upper()}]"
                logger.info(f"📡 Scanning {target} {scan_label} [{service.service}] with {len(templates)} template(s)")
                logger.debug(f"   Templates: {', '.join([t.split('/')[-1] for t in templates])}")
                findings = self._execute_nuclei(target, templates, scan_type, service)
                
                if findings:
                    logger.info(f"✅ Found {len(findings)} result(s) for {target} {scan_label}")
                else:
                    logger.info(f"❌ No matches for {target} {scan_label}")
                    
                all_findings.extend(findings)
                templates_used.extend(templates)
        
        return all_findings, list(set(templates_used))
    
    def _execute_nuclei(self, target: str, templates: List[str], scan_type: str, service: ServiceInfo = None) -> List[Dict]:
        """Execute nuclei scan"""
        cmd = [self.nuclei_path, '-duc', '-ni', '-silent', '-u', target]
        
        # Add templates with full paths if templates_dir is provided
        for template in templates:
            if self.templates_dir:
                # Use full path to template
                template_path = str(Path(self.templates_dir) / template)
                cmd.extend(['-t', template_path])
            else:
                # Use relative path (relies on Nuclei's default template location)
                cmd.extend(['-t', template])
        
        # Add common flags
        cmd.extend([
            '-jsonl',
            '-rate-limit', str(self.rate_limit),
            '-timeout', '10',
            '-retries', '1'
        ])
        
        # Dry-run mode
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {' '.join(cmd)}")
            return []
        
        # Show command if verbose mode is enabled
        if logger.level == logging.DEBUG:
            logger.info(f"🔧 Executing: {' '.join(cmd)}")
        
        findings = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            # Add metadata about scan type
                            finding['_scan_type'] = scan_type
                            # Normalize host field for CTEM ingester compatibility
                            # The ingester expects 'host' to be a URL with scheme (e.g., http://IP:port or tcp://IP:port)
                            if 'url' in finding:
                                url = finding['url']
                                # For network scans, nuclei provides url without scheme (e.g., "10.0.0.1:3306")
                                # Add scheme based on finding type
                                if '://' not in url:
                                    finding_type = finding.get('type', 'tcp')
                                    url = f"{finding_type}://{url}"
                                finding['host'] = url
                            
                            # CRITICAL: Enrich finding with CTEM metadata for resource and data_class population
                            finding = enrich_nuclei_finding(finding, service)
                            
                            # Attach service info for schema conversion later
                            finding['_service'] = asdict(service) if service else None
                            
                            findings.append(finding)
                        except json.JSONDecodeError:
                            pass
            # Log stderr only if there are actual errors (not just nuclei banner/info)
            if result.stderr and logger.level == logging.DEBUG:
                # Filter out nuclei's informational messages
                stderr_lines = [line for line in result.stderr.split('\n') 
                               if line.strip() and not any(x in line for x in [
                                   'projectdiscovery.io', '__', '[VER]', '[INF]', 
                                   'Current nuclei', 'Started metrics', 'Saved', 'templates'
                               ])]
                if stderr_lines:
                    logger.debug(f"Nuclei stderr: {' '.join(stderr_lines[:3])}")
        except subprocess.TimeoutExpired:
            logger.warning(f"⏱️  Scan timed out for {target}")
        except Exception as e:
            logger.error(f"❌ Error executing nuclei: {e}")
        
        sys.stdout.flush()
        sys.stderr.flush()
        return findings


def convert_to_schema_event(
    finding: Dict,
    service: ServiceInfo,
    office_id: str,
    scanner_id: str,
    scan_timestamp: datetime,
    scan_run_id: Optional[str] = None
) -> Dict:
    """
    Convert a nuclei finding to schema-compliant exposure event.
    
    Args:
        finding: Nuclei finding with enrichment
        service: ServiceInfo with MAC, hostname, etc.
        office_id: Office identifier
        scanner_id: Scanner instance identifier
        scan_timestamp: Timestamp of the scan
        scan_run_id: Optional scan run ID for correlation
    
    Returns:
        Schema-compliant event dictionary
    """
    enrichment = finding.get('_ctem_enrichment', {})
    info = finding.get('info', {})
    
    # Extract host information
    from urllib.parse import urlparse
    host_url = finding.get('host', '')
    parsed = urlparse(host_url)
    ip = parsed.hostname or service.host
    port = parsed.port
    
    # Generate IDs
    event_id = f"evt_{uuid7()}"
    
    # Generate exposure ID (deterministic for deduplication)
    mac_or_ip = service.mac if service.mac else service.host
    exposure_components = f"{office_id}|{mac_or_ip}|{ip}|{port}|{enrichment.get('template_id', 'unknown')}"
    exposure_id = f"exp_{sha256(exposure_components.encode()).hexdigest()[:32]}"
    
    # Generate dedupe key
    dedupe_components = f"{office_id}|{mac_or_ip}|{ip}|{port}|{enrichment.get('template_id')}"
    dedupe_key = sha256(dedupe_components.encode()).hexdigest()[:32]
    
    # Map nuclei severity to numeric score
    severity_map = {
        'critical': 95,
        'high': 80,
        'medium': 60,
        'low': 40,
        'info': 20,
        'unknown': 30
    }
    severity_score = severity_map.get(info.get('severity', 'info').lower(), 30)
    
    # Map to exposure class
    exposure_class = _map_exposure_class(enrichment, info)
    
    # Determine transport
    transport = enrichment.get('transport', 'tcp').lower()
    if transport not in ['tcp', 'udp', 'icmp']:
        transport = 'tcp'
    
    # Determine protocol
    protocol = parsed.scheme or 'unknown'
    
    # Build schema-compliant event
    event = {
        "schema_version": "1.0.0",
        "@timestamp": scan_timestamp.isoformat(),
        
        "event": {
            "id": event_id,
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": "exposure_opened",
            "severity": severity_score,
            "correlation": {
                "dedupe_key": dedupe_key
            }
        },
        
        "office": {
            "id": office_id,
            "name": f"Office-{office_id}"
        },
        
        "scanner": {
            "id": scanner_id,
            "type": "nuclei",
            "version": finding.get('nuclei-version', 'unknown')
        },
        
        "target": {
            "asset": {
                "id": service.mac if service.mac else f"XX:XX:XX_{service.host}",
                "ip": [ip],
            }
        },
        
        "exposure": {
            "id": exposure_id,
            "class": exposure_class,
            "status": "open",
            "vector": {
                "transport": transport,
                "protocol": protocol,
                "dst": {
                    "ip": ip,
                },
                "network_direction": "internal"
            },
            "service": {
                "name": enrichment.get('template_id', 'unknown'),
                "product": info.get('name', 'unknown'),
            },
            "first_seen": scan_timestamp.isoformat(),
            "last_seen": scan_timestamp.isoformat()
        }
    }
    
    # Add optional fields
    if scan_run_id:
        event['event']['correlation']['scan_run_id'] = scan_run_id
    
    if service.hostname:
        event['target']['asset']['hostname'] = service.hostname
    
    if service.mac:
        event['target']['asset']['mac'] = service.mac
    
    # Add OS if available from service context
    if service.os:
        event['target']['asset']['os'] = service.os
    
    if port:
        event['exposure']['vector']['dst']['port'] = port
    
    # Add service version if available
    if service.version:
        event['exposure']['service']['version'] = service.version
    
    # Add resource if available from enrichment
    if enrichment.get('resource_type') and enrichment.get('resource_identifier'):
        event['exposure']['resource'] = {
            "type": enrichment['resource_type'],
            "identifier": enrichment['resource_identifier']
        }
        if enrichment.get('evidence_hash'):
            event['exposure']['resource']['evidence_hash'] = enrichment['evidence_hash']
    
    # Add data classifications if available
    if enrichment.get('data_classifications'):
        event['exposure']['data_class'] = enrichment['data_classifications']
    
    return event


def _map_exposure_class(enrichment: Dict, info: Dict) -> str:
    """Map nuclei finding to exposure class."""
    tags = [tag.lower() for tag in info.get('tags', [])]
    template_id = enrichment.get('template_id', '').lower()
    
    # Database exposures
    if any(keyword in tags for keyword in ['database', 'mongodb', 'mysql', 'postgresql', 'redis', 'db']):
        return 'db_exposed'
    
    # Container APIs
    if any(keyword in tags for keyword in ['docker', 'kubernetes', 'k8s', 'container']):
        return 'container_api_exposed'
    
    # Remote admin interfaces
    if any(keyword in tags for keyword in ['admin', 'ssh', 'rdp', 'vnc', 'telnet']):
        return 'remote_admin_exposed'
    
    # Debug/admin panels
    if any(keyword in template_id for keyword in ['debug', 'console', 'panel', 'dashboard']):
        return 'debug_port_exposed'
    if any(keyword in tags for keyword in ['debug', 'console', 'panel']):
        return 'debug_port_exposed'
    
    # File shares
    if any(keyword in tags for keyword in ['smb', 'nfs', 'ftp', 'fileshare']):
        return 'fileshare_exposed'
    
    # VCS protocols
    if any(keyword in tags for keyword in ['git', 'svn', 'cvs', 'vcs']):
        return 'vcs_protocol_exposed'
    
    # HTTP content leaks
    if any(keyword in tags for keyword in ['exposure', 'disclosure', 'leak']):
        return 'http_content_leak'
    
    # mDNS service advertisement
    if any(keyword in tags for keyword in ['mdns', 'bonjour', 'zeroconf']):
        return 'service_advertised_mdns'
    
    # Egress tunnel indicators
    if any(keyword in tags for keyword in ['tunnel', 'proxy', 'socks', 'vpn']):
        return 'egress_tunnel_indicator'
    
    # Default
    return 'unknown_service_exposed'


def build_host_structure(services: List[ServiceInfo], os_info_list: List[OSInfo]) -> List[Dict]:
    """Build host-centric data structure"""
    os_map = {os.host: asdict(os) for os in os_info_list}
    hosts_services = {}
    
    for service in services:
        if service.host not in hosts_services:
            hosts_services[service.host] = []
        hosts_services[service.host].append(service)
    
    host_centric = []
    for host, host_services in sorted(hosts_services.items()):
        host_entry = {
            "host": host,
            "os": os_map.get(host),
            "exposures": [asdict(s) for s in host_services]
        }
        
        # Remove redundant host fields
        for exposure in host_entry["exposures"]:
            exposure.pop("host", None)
        if host_entry["os"]:
            host_entry["os"].pop("host", None)
        
        host_centric.append(host_entry)
    
    return host_centric


def process_files(file_paths: List[Path]) -> Tuple[List[ServiceInfo], List[OSInfo]]:
    """Process multiple files (XML, GNMAP, or open_ports_summary.txt) and aggregate results"""
    all_services = []
    all_os_info = []
    
    for file_path in file_paths:
        try:
            if file_path.suffix == '.xml':
                services, os_info = NmapParser.parse_xml(str(file_path))
                all_services.extend(services)
                all_os_info.extend(os_info)
                logger.debug(f"Parsed {file_path.name}: {len(services)} services")
            elif file_path.suffix == '.gnmap':
                services = NmapParser.parse_gnmap(str(file_path))
                all_services.extend(services)
                logger.debug(f"Parsed {file_path.name}: {len(services)} services")
            elif file_path.name == 'open_ports_summary.txt' or 'open_ports' in file_path.name:
                services = parse_open_ports_summary(str(file_path))
                all_services.extend(services)
                logger.info(f"Parsed {file_path.name}: {len(services)} services")
            else:
                logger.warning(f"Skipping unsupported file type: {file_path.name}")
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            continue
    
    return all_services, all_os_info


def main():
    parser = argparse.ArgumentParser(
        description='Automated Nuclei scanner with nmap integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i scan.xml
  %(prog)s -i scan.xml -o results.json
  %(prog)s -i open_ports_summary.txt -o results.json
  %(prog)s -d /path/to/scan/directory -o results.json
  %(prog)s -i scan.xml --dry-run
  
  # With schema-compliant output for CTEM ingestion:
  %(prog)s -i scan.xml --schema-output --office-id office-123 --scanner-id scanner-001
  
Supported Input Formats:
  - Nmap XML (.xml) - Full service detection with version info
  - Nmap GNMAP (.gnmap) - Service detection with basic info
  - Open Ports Summary (open_ports_summary.txt) - Port-only detection
  - Directory mode: Automatically processes all supported files
  
Detection Strategy:
  - Network-only: Pure protocol detection (SSH, FTP, databases)
  - HTTP-only: Web service detection (most HTTP ports)
  - Both: Ambiguous ports tested as BOTH network AND HTTP
    Example: Port 9100 (HP JetDirect printer vs Prometheus exporter)
  
Output Files:
  - Main results file (specified by -o)
  - *_nuclei_only.json - Enriched nuclei findings
  - *_schema.json - Schema-compliant events (when --schema-output is used)
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-i', '--input', help='Single scan file (XML, GNMAP, or open_ports_summary.txt)')
    input_group.add_argument('-d', '--directory', help='Directory containing scan files (XML, GNMAP, open_ports_summary.txt)')
    
    parser.add_argument('-o', '--output', default='nuclei_results.json', help='Output JSON file')
    parser.add_argument('--nuclei-path', default='nuclei', help='Path to nuclei binary')
    parser.add_argument('--templates-dir', help='Path to nuclei-templates directory (optional, nuclei will use its default if not specified)')
    parser.add_argument('--rate-limit', type=int, default=30, help='Nuclei rate limit (default: 30)')
    parser.add_argument('-dr','--dry-run', action='store_true', help='Dry-run mode (show commands without executing)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # CTEM ingestion parameters
    parser.add_argument('--office-id', default='default-office', help='Office/site identifier for CTEM ingestion (default: default-office)')
    parser.add_argument('--scanner-id', default='nmap2nuclei-scanner', help='Scanner instance identifier (default: nmap2nuclei-scanner)')
    parser.add_argument('--scan-run-id', help='Optional scan run ID for correlation')
    parser.add_argument('--schema-output', action='store_true', help='Output in schema-compliant format for direct CTEM ingestion')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Determine input files
    input_files = []
    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            logger.error(f"Input file not found: {args.input}")
            sys.exit(1)
        input_files = [input_path]
        logger.info(f"Processing single file: {args.input}")
    elif args.directory:
        dir_path = Path(args.directory)
        if not dir_path.exists() or not dir_path.is_dir():
            logger.error(f"Directory not found or not a directory: {args.directory}")
            sys.exit(1)
        
        # Collect XML, GNMAP, and open_ports_summary files
        input_files = []
        input_files.extend(list(dir_path.glob('*.xml')))
        input_files.extend(list(dir_path.glob('*.gnmap')))
        
        # Check for open_ports_summary.txt
        open_ports_file = dir_path / 'open_ports_summary.txt'
        if open_ports_file.exists():
            input_files.append(open_ports_file)
        
        if not input_files:
            logger.error(f"No supported files (XML, GNMAP, open_ports_summary.txt) found in directory: {args.directory}")
            sys.exit(1)
        logger.info(f"Found {len(input_files)} file(s) in directory")
    
    # Parse nmap results
    logger.info(f"Parsing scan results from {len(input_files)} file(s)...")
    services, os_info_list = process_files(input_files)
    
    if not services:
        logger.error("No services found in nmap results")
        sys.exit(1)
    
    logger.info(f"Found {len(services)} open services across {len(set(s.host for s in services))} hosts")
    
    # Display OS detection
    if os_info_list:
        logger.info(f"OS detection results for {len(os_info_list)} hosts:")
        for os in os_info_list:
            logger.info(f"  {os.host}: {os.os_match} ({os.accuracy}% accuracy)")
    
    # Display services
    for service in services:
        logger.info(f"  {service.host}:{service.port}/{service.protocol} - {service.service} {service.version}")
    
    # Dry-run notice
    if args.dry_run:
        logger.warning("=" * 60)
        logger.warning("DRY-RUN MODE: Commands will be displayed but not executed")
        logger.warning("=" * 60)
    
    # Initialize scanner and run scans
    scanner = NucleiScanner(
        nuclei_path=args.nuclei_path,
        rate_limit=args.rate_limit,
        dry_run=args.dry_run,
        templates_dir=args.templates_dir
    )
    
    all_findings, templates_used = scanner.scan_services(services)
    
    # Build output structure
    host_centric_data = build_host_structure(services, os_info_list)
    
    # Determine input source for metadata
    if args.input:
        input_source = str(Path(args.input).absolute())
        input_type = 'single_file'
    else:
        input_source = str(Path(args.directory).absolute())
        input_type = 'directory'
    
    # Get scan timestamp
    scan_timestamp = datetime.now(timezone.utc)
    
    # Convert findings to schema-compliant events if requested
    schema_events = []
    if args.schema_output:
        logger.info("Converting findings to schema-compliant format...")
        for finding in all_findings:
            # Get service info from finding (attached during scan)
            service_dict = finding.get('_service')
            if service_dict:
                # Reconstruct ServiceInfo from dict
                service = ServiceInfo(**service_dict)
                
                # Convert to schema event
                event = convert_to_schema_event(
                    finding=finding,
                    service=service,
                    office_id=args.office_id,
                    scanner_id=args.scanner_id,
                    scan_timestamp=scan_timestamp,
                    scan_run_id=args.scan_run_id
                )
                schema_events.append(event)
        
        logger.info(f"Converted {len(schema_events)} findings to schema format")
    
    results = {
        'scan_metadata': {
            'timestamp': scan_timestamp.isoformat(),
            'input_type': input_type,
            'input_source': input_source,
            'files_processed': len(input_files),
            'total_hosts': len(set(s.host for s in services)),
            'total_services': len(services),
        },
        'hosts': host_centric_data,
        'nuclei_findings': all_findings,
        'templates_executed': templates_used,
        'summary': {
            'total_findings': len(all_findings),
            'findings_by_severity': {}
        }
    }
    
    # Calculate severity distribution
    for finding in all_findings:
        severity = finding.get('info', {}).get('severity', 'unknown')
        results['summary']['findings_by_severity'][severity] = \
            results['summary']['findings_by_severity'].get(severity, 0) + 1
    
    # Save results
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Results saved to: {output_path}")
    
    # Save schema-compliant events if generated
    if schema_events:
        schema_path = output_path.parent / f"{output_path.stem}_schema.json"
        with open(schema_path, 'w') as f:
            json.dump(schema_events, f, indent=2)
        logger.info(f"Schema-compliant events saved to: {schema_path} (ready for CTEM ingestion)")
    
    # Also save nuclei findings in enriched format (legacy)
    if all_findings:
        nuclei_only_path = output_path.parent / f"{output_path.stem}_nuclei_only.json"
        with open(nuclei_only_path, 'w') as f:
            json.dump(all_findings, f, indent=2)
        logger.info(f"Nuclei-only findings saved to: {nuclei_only_path} (enriched format)")
    
    logger.info(f"Total findings: {len(all_findings)}")
    
    # Display summary
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Hosts scanned: {results['scan_metadata']['total_hosts']}")
    print(f"Services found: {results['scan_metadata']['total_services']}")
    print(f"Total findings: {results['summary']['total_findings']}")
    print("\nFindings by severity:")
    for severity, count in sorted(results['summary']['findings_by_severity'].items()):
        print(f"  {severity.upper()}: {count}")
    print("=" * 60)


if __name__ == '__main__':
    main()
