package main

// Service detection database and logic
// Maps common ports to their typical services

// commonServices maps well-known port numbers to service names
var commonServices = map[int]string{
	// Standard ports (RFC 1700)
	20:  "ftp-data",
	21:  "ftp",
	22:  "ssh",
	23:  "telnet",
	25:  "smtp",
	53:  "dns",
	67:  "dhcp-server",
	68:  "dhcp-client",
	69:  "tftp",
	80:  "http",
	110: "pop3",
	119: "nntp",
	123: "ntp",
	135: "msrpc",
	137: "netbios-ns",
	138: "netbios-dgm",
	139: "netbios-ssn",
	143: "imap",
	161: "snmp",
	162: "snmp-trap",
	179: "bgp",
	389: "ldap",
	443: "https",
	445: "microsoft-ds",
	465: "smtps",
	514: "syslog",
	515: "printer",
	587: "smtp-submission",
	631: "ipp",
	636: "ldaps",
	873: "rsync",
	902: "vmware-auth",
	989: "ftps-data",
	990: "ftps",
	993: "imaps",
	995: "pop3s",

	// Database ports
	1433:  "mssql",
	1434:  "mssql-mon",
	1521:  "oracle",
	3050:  "firebird",
	3306:  "mysql",
	5432:  "postgresql",
	5984:  "couchdb",
	6379:  "redis",
	7000:  "cassandra",
	7001:  "cassandra-thrift",
	8086:  "influxdb",
	9042:  "cassandra-cql",
	9200:  "elasticsearch",
	9300:  "elasticsearch-cluster",
	27017: "mongodb",
	27018: "mongodb-shard",
	27019: "mongodb-config",
	28015: "rethinkdb",
	28017: "mongodb-http",

	// Web services and proxies
	591:  "filemaker",
	593:  "http-rpc-epmap",
	808:  "http-alt",
	1080: "socks",
	1900: "upnp",
	2222: "directadmin",
	3000: "ppp",
	3128: "squid-proxy",
	5000: "upnp",
	8000: "http-alt",
	8001: "vcom-tunnel",
	8008: "http-alt",
	8009: "ajp13",
	8080: "http-proxy",
	8081: "blackice",
	8090: "http-alt",
	8180: "http-alt",
	8443: "https-alt",
	8888: "sun-answerbook",
	9000: "cslistener",
	9001: "tor-orport",
	9030: "tor-dirport",
	9090: "zeus-admin",
	9091: "xmltec-xmlmail",

	// Message queues and streaming
	4369:  "epmd",
	5222:  "xmpp-client",
	5269:  "xmpp-server",
	5672:  "amqp",
	6667:  "irc",
	9092:  "kafka",
	15672: "rabbitmq-management",
	25672: "rabbitmq-dist",
	61613: "stomp",
	61614: "stomp-ssl",
	61616: "activemq",

	// Remote access
	// Duplicate of line 11
	//22:   "ssh",
	// Duplicate of line 12
	//23:   "telnet",
	3389: "rdp",
	5900: "vnc",
	5901: "vnc-1",
	5902: "vnc-2",
	5903: "vnc-3",
	5904: "vnc-4",
	5905: "vnc-5",

	// Application servers
	4848: "glassfish-admin",
	// Duplicate of line 56
	//7001: "weblogic",
	7002: "weblogic-ssl",
	8005: "tomcat-shutdown",
	// Duplicate of line 80
	//8009: "tomcat-ajp",
	// Duplicate of line 81
	//8080: "tomcat",
	// Duplicate of line 85
	//8443: "tomcat-ssl",
	9990:  "jboss-management",
	10000: "webmin",
	10001: "webmin-ssl",

	// Version control and CI/CD
	// Duplicate of line 73
	//2222: "git-ssh",
	// Duplicate of line 74
	//3000: "node-dev",
	4567: "sinatra",
	// Duplicate of line 81
	//8080: "jenkins",
	// Duplicate of line 82
	//8081: "nexus",
	// Duplicate of line 87
	//9000:  "sonarqube",
	50000: "jenkins-agent",

	// Container and orchestration
	2375: "docker",
	2376: "docker-tls",
	2377: "docker-swarm",
	4243: "docker-alt",
	5001: "docker-registry",
	6443: "kubernetes-api",
	// Duplicate of line 78
	//8001:  "kubernetes-proxy",
	10250: "kubelet",
	10251: "kube-scheduler",
	10252: "kube-controller",

	// Monitoring and metrics
	// Duplicate of line 74
	//3000: "grafana",
	4000: "icinga2",
	// Duplicate of line 57
	//8086: "influxdb",
	// Duplicate of line 90
	//9090: "prometheus",
	9093: "alertmanager",
	9100: "node-exporter",
	9115: "blackbox-exporter",
	9187: "postgres-exporter",

	// Gaming and media
	25565: "minecraft",
	27015: "source-engine",
	27016: "source-rcon",
	3074:  "xbox-live",
	3478:  "steam",
	3479:  "steam-alt",
	4380:  "unityhub",
	8767:  "teamspeak-fileserver",
	9987:  "teamspeak",
	10011: "teamspeak-serverquery",
	25575: "minecraft-rcon",

	// Security and VPN
	500:  "isakmp",
	1194: "openvpn",
	1701: "l2tp",
	1723: "pptp",
	4500: "ipsec-nat-t",
	8834: "nessus",

	// IoT and smart devices
	1883: "mqtt",
	// Duplicate of line 72
	//1900: "upnp-discovery",
	5353: "mdns",
	8883: "mqtt-ssl",

	// Development and debugging
	// Duplicate of line 74
	//3000:  "node-dev",
	3001: "node-dev-alt",
	4200: "angular-dev",
	// Duplicate of line 76
	//5000:  "flask-dev",
	5173: "vite-dev",
	// Duplicate of line 77
	//8000:  "django-dev",
	// Duplicate of line 81
	//8080:  "spring-boot",
	// Duplicate of line 82
	//8081:  "actuator",
	35729: "livereload",

	// Mail services
	// Duplicate of line 13
	//25:   "smtp",
	// Duplicate of line 19
	//110:  "pop3",
	// Duplicate of line 26
	//143:  "imap",
	// Duplicate of line 33
	//465:  "smtps",
	// Duplicate of line 36
	//587:  "smtp-submission",
	// Duplicate of line 43
	//993:  "imaps",
	// Duplicate of line 44
	//995:  "pop3s",
	2525: "smtp-alt",

	// File sharing
	// Duplicate of line 10
	//21:   "ftp",
	// Duplicate of line 11
	//22:   "sftp",
	// Duplicate of line 17
	//69:   "tftp",
	// Duplicate of line 25
	//139:  "smb",
	// Duplicate of line 32
	//445:  "smb-direct",
	2049: "nfs",
	// Duplicate of line 91
	//9091: "transmission",
	51413: "transmission-peer",

	// Miscellaneous
	111: "rpcbind",
	264: "bgmp",
	497: "retrospect",
	512: "exec",
	513: "login",
	// Duplicate of line 34
	//514:   "shell",
	543: "klogin",
	544: "kshell",
	548: "afp",
	// Duplicate of line 47
	//1433:  "mssql",
	2082: "cpanel",
	2083: "cpanel-ssl",
	2086: "whm",
	2087: "whm-ssl",
	2095: "webmail",
	2096: "webmail-ssl",
	5060: "sip",
	5061: "sip-tls",
	6000: "x11",
	8291: "mikrotik-winbox",
	// Duplicate of line 132
	//10000: "webmin",
	20000: "dnp",
}

// detectService returns the service name for a given port
// Returns "unknown" if the port is not recognized
func detectService(port int) string {
	if service, ok := commonServices[port]; ok {
		return service
	}
	return "unknown"
}

// getServiceByPort is an alias for detectService for API consistency
func getServiceByPort(port int) string {
	return detectService(port)
}

// isCommonPort checks if a port is in the common services database
func isCommonPort(port int) bool {
	_, exists := commonServices[port]
	return exists
}

// getAllKnownPorts returns a slice of all ports with known services
func getAllKnownPorts() []int {
	ports := make([]int, 0, len(commonServices))
	for port := range commonServices {
		ports = append(ports, port)
	}
	return ports
}
