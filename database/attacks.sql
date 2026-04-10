-- ================================================================
--  SIEM Africa — Signatures d'attaques contextualisées Afrique
--  Fichier  : 2-database/attacks.sql
--  Version  : 1.0 — 400 signatures
--  Sources  : INTERPOL Africa 2024/2025, Snort Community, Wazuh
-- ================================================================
--
--  Gravité : 1=Faible | 2=Moyenne | 3=Haute | 4=Critique
--  Catégories :
--    Brute Force | Reconnaissance | Web Attack | DoS | DDoS
--    Ransomware | Malware | Crypto | Phishing | BEC
--    Intrusion | Privilege Escalation | Lateral Movement
--    C2 | Exfiltration | Mobile
-- ================================================================

INSERT OR IGNORE INTO attaques
(rule_id,sid_snort,nom,nom_en,categorie,description,description_en,
 gravite,action_recommandee,contre_mesure,faux_positif,source,
 protocole,port_cible,cve,frequence_afrique)
VALUES

-- ================================================================
-- 1. BRUTE FORCE — 60 entrées
-- ================================================================

(5763,2001219,'SSH Brute Force','SSH Brute Force','Brute Force',
'Tentatives répétées de connexion SSH par force brute. Attaque la plus fréquente sur les serveurs Linux des PME africaines.',
'Repeated SSH brute force login attempts. Most frequent attack on African SME Linux servers.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 22 -j DROP',0,'Wazuh','TCP',22,NULL,'Très commune'),

(5762,2001220,'SSH Brute Force Distribué','Distributed SSH Brute Force','Brute Force',
'Attaque SSH coordonnée depuis plusieurs IPs — indique un botnet organisé.',
'SSH attack coordinated from multiple IPs — indicates organized botnet.',
4,'Bloquer IP','iptables -A INPUT -p tcp --dport 22 -j DROP',0,'Wazuh','TCP',22,NULL,'Très commune'),

(5760,2001221,'SSH Login Échoué','SSH Failed Login','Brute Force',
'Tentative SSH avec identifiants incorrects. Peut être un utilisateur légitime ou une tentative isolée.',
'SSH login with incorrect credentials.',
2,'Alerter',NULL,1,'Wazuh','TCP',22,NULL,'Très commune'),

(5756,2001222,'SSH Clé Invalide','SSH Invalid Key','Brute Force',
'Clé SSH invalide ou non autorisée. Peut indiquer une tentative avec clé volée.',
'Invalid or unauthorized SSH key attempt.',
3,'Alerter',NULL,0,'Wazuh','TCP',22,NULL,'Commune'),

(20100,2001240,'RDP Brute Force','RDP Brute Force','Brute Force',
'Attaque brute force sur bureau à distance Windows (RDP). Très ciblé sur PME africaines sous Windows Server.',
'Brute force on Windows Remote Desktop. Heavily targeted at African SMEs using Windows Server.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 3389 -j DROP',0,'Snort','TCP',3389,NULL,'Très commune'),

(20101,2001241,'RDP Login Échoué Multiple','Multiple RDP Login Failures','Brute Force',
'Plusieurs échecs de connexion RDP depuis la même IP.',
'Multiple RDP login failures from same IP.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 3389 -j DROP',0,'Snort','TCP',3389,NULL,'Très commune'),

(18100,2001230,'FTP Brute Force','FTP Brute Force','Brute Force',
'Tentatives répétées de connexion FTP. Très utilisé dans les PME africaines.',
'Repeated FTP login attempts. Widely used in African SMEs.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 21 -j DROP',0,'Snort','TCP',21,NULL,'Très commune'),

(18101,2001231,'FTP Login Anonyme','Anonymous FTP Login','Brute Force',
'Connexion FTP anonyme — accès non authentifié aux fichiers du serveur.',
'Anonymous FTP login — unauthenticated file access.',
3,'Alerter','iptables -A INPUT -s {IP} -p tcp --dport 21 -j DROP',0,'Snort','TCP',21,NULL,'Commune'),

(20200,2001260,'HTTP Login Brute Force','HTTP Login Brute Force','Brute Force',
'Force brute sur une page de connexion web. Très utilisée contre les portails admin.',
'Brute force on web login page. Used against admin portals.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(20201,2001261,'HTTPS Login Brute Force','HTTPS Login Brute Force','Brute Force',
'Force brute sur connexion HTTPS. Tente de contourner l authentification sécurisée.',
'Brute force on HTTPS login.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,NULL,'Très commune'),

(20202,2001262,'WordPress Login Brute Force','WordPress Brute Force','Brute Force',
'Attaque sur wp-login.php. WordPress massivement utilisé par les PME africaines.',
'Attack on wp-login.php. WordPress massively used by African SMEs.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(20203,2001263,'WordPress XMLRPC Brute Force','WordPress XMLRPC Brute Force','Brute Force',
'Brute force via XML-RPC WordPress — contourne les protections du formulaire de connexion.',
'WordPress XML-RPC brute force — bypasses login form protections.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(20204,2001264,'Joomla Brute Force','Joomla CMS Brute Force','Brute Force',
'Attaque sur le portail admin Joomla. CMS fréquemment utilisé en Afrique.',
'Attack on Joomla admin portal.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(20150,2001250,'MySQL Brute Force','MySQL Brute Force','Brute Force',
'Tentatives répétées de connexion MySQL — risque compromission données clients.',
'Repeated MySQL connection attempts — customer data compromise risk.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 3306 -j DROP',0,'Snort','TCP',3306,NULL,'Commune'),

(20151,2001251,'PostgreSQL Brute Force','PostgreSQL Brute Force','Brute Force',
'Tentatives répétées de connexion PostgreSQL.',
'Repeated PostgreSQL connection attempts.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 5432 -j DROP',0,'Snort','TCP',5432,NULL,'Commune'),

(20318,2001298,'MongoDB Brute Force','MongoDB Brute Force','Brute Force',
'MongoDB souvent exposé sans authentification en Afrique. Cible très fréquente.',
'MongoDB often exposed without auth in Africa. Very frequent target.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 27017 -j DROP',0,'Snort','TCP',27017,NULL,'Très commune'),

(20319,2001299,'Redis Brute Force','Redis Brute Force','Brute Force',
'Redis exposé sans mot de passe sur les serveurs africains.',
'Redis exposed without password on African servers.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 6379 -j DROP',0,'Snort','TCP',6379,NULL,'Très commune'),

(20320,2001300,'Elasticsearch Brute Force','Elasticsearch Brute Force','Brute Force',
'Clusters Elasticsearch souvent exposés sans sécurité.',
'Elasticsearch clusters often exposed without security.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 9200 -j DROP',0,'Snort','TCP',9200,NULL,'Commune'),

(20321,2001301,'MSSQL Brute Force','MSSQL Brute Force','Brute Force',
'Brute force sur Microsoft SQL Server. Ciblé dans les PME Windows.',
'Brute force on Microsoft SQL Server.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 1433 -j DROP',0,'Snort','TCP',1433,NULL,'Commune'),

(20250,2001270,'SMTP Auth Brute Force','SMTP Auth Brute Force','Brute Force',
'Tentatives répétées d authentification SMTP — peut mener à envoi de spam.',
'Repeated SMTP auth attempts — can lead to spam.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 25 -j DROP',0,'Snort','TCP',25,NULL,'Commune'),

(20251,2001271,'POP3 Brute Force','POP3 Brute Force','Brute Force',
'Attaque brute force sur le service de messagerie POP3.',
'Brute force on POP3 mail service.',
2,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 110 -j DROP',0,'Snort','TCP',110,NULL,'Commune'),

(20252,2001272,'IMAP Brute Force','IMAP Brute Force','Brute Force',
'Brute force sur IMAP — accès potentiel à tous les emails.',
'IMAP brute force — potential access to all emails.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 143 -j DROP',0,'Snort','TCP',143,NULL,'Commune'),

(20300,2001280,'Telnet Brute Force','Telnet Brute Force','Brute Force',
'Telnet transmet mots de passe en clair — protocole très dangereux.',
'Telnet transmits passwords in clear text — very dangerous protocol.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 23 -j DROP',0,'Snort','TCP',23,NULL,'Commune'),

(20301,2001281,'VNC Brute Force','VNC Brute Force','Brute Force',
'Brute force VNC — contrôle total d un poste de travail.',
'VNC brute force — full workstation control.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 5900 -j DROP',0,'Snort','TCP',5900,NULL,'Commune'),

(20302,2001282,'phpMyAdmin Brute Force','phpMyAdmin Brute Force','Brute Force',
'Outil phpMyAdmin exposé sur de nombreux serveurs africains.',
'phpMyAdmin exposed on many African servers.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(20315,2001295,'Docker API Brute Force','Docker API Brute Force','Brute Force',
'API Docker exposée — compromission totale du serveur possible.',
'Exposed Docker API — full server compromise possible.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 2375 -j DROP',0,'Snort','TCP',2375,NULL,'Commune'),

(20316,2001296,'Jenkins Brute Force','Jenkins Brute Force','Brute Force',
'Brute force sur serveur Jenkins CI/CD.',
'Brute force on Jenkins CI/CD server.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 8080 -j DROP',0,'Snort','TCP',8080,NULL,'Commune'),

(20325,2001305,'LDAP Brute Force','LDAP Brute Force','Brute Force',
'Brute force sur annuaire LDAP / Active Directory.',
'Brute force on LDAP directory / Active Directory.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 389 -j DROP',0,'Snort','TCP',389,NULL,'Commune'),

(20327,2001307,'SIP VoIP Brute Force','SIP VoIP Brute Force','Brute Force',
'Brute force VoIP SIP — appels frauduleux aux frais de la PME.',
'SIP VoIP brute force — fraudulent calls at SME expense.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 5060 -j DROP',0,'Snort','UDP',5060,NULL,'Commune'),

(20333,2001313,'Password Spraying','Password Spraying Attack','Brute Force',
'Un seul mot de passe testé sur de nombreux comptes pour éviter le verrouillage.',
'Single password tested on many accounts to avoid lockout.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(20334,2001314,'Credential Stuffing','Credential Stuffing Attack','Brute Force',
'Utilisation de credentials volés lors d autres fuites de données.',
'Use of credentials stolen from other data breaches.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(20335,2001315,'Reverse Brute Force','Reverse Brute Force','Brute Force',
'Mot de passe connu testé sur plusieurs comptes utilisateurs.',
'Known password tested against multiple user accounts.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(20336,2001316,'SMB Login Brute Force','SMB Login Brute Force','Brute Force',
'Tentatives répétées d authentification SMB sur partages Windows.',
'Repeated SMB auth attempts on Windows shares.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 445 -j DROP',0,'Snort','TCP',445,NULL,'Commune'),

(20340,2001320,'OTP Bypass Brute Force','OTP Code Brute Force','Brute Force',
'Brute force codes OTP 6 chiffres — contournement 2FA.',
'6-digit OTP code brute force — 2FA bypass.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Commune'),

(20341,2001321,'cPanel Brute Force','cPanel Brute Force','Brute Force',
'Brute force sur cPanel — hébergement très commun en Afrique.',
'cPanel brute force — very common hosting in Africa.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 2083 -j DROP',0,'Snort','TCP',2083,NULL,'Commune'),

(20342,2001322,'Webmin Brute Force','Webmin Brute Force','Brute Force',
'Brute force sur Webmin — outil administration Linux.',
'Webmin Linux admin tool brute force.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 10000 -j DROP',0,'Snort','TCP',10000,NULL,'Commune'),

(20343,2001323,'Roundcube Webmail Brute Force','Roundcube Brute Force','Brute Force',
'Brute force sur Roundcube — webmail très répandu sur hébergements africains.',
'Roundcube webmail brute force — common in African hosting.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(20344,2001324,'Zimbra Webmail Brute Force','Zimbra Brute Force','Brute Force',
'Brute force Zimbra — serveur mail utilisé par entreprises africaines.',
'Zimbra mail server brute force.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,NULL,'Commune'),

(20345,2001325,'OpenVPN Brute Force','OpenVPN Brute Force','Brute Force',
'Brute force sur serveur VPN OpenVPN.',
'OpenVPN server brute force.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 1194 -j DROP',0,'Snort','UDP',1194,NULL,'Commune'),

(20346,2001326,'OWA Exchange Brute Force','Outlook Web App Brute Force','Brute Force',
'Brute force sur Outlook Web App Exchange — entreprises Microsoft.',
'Brute force on Outlook Web App Exchange.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,NULL,'Commune'),

(20347,2001327,'SAP Business Brute Force','SAP Business Login Brute Force','Brute Force',
'Brute force sur portail SAP Business One — ERP grandes PME africaines.',
'Brute force on SAP Business One portal.',
3,'Alerter',NULL,0,'Snort','TCP',8080,NULL,'Rare'),

(20348,2001328,'Postfix SASL Brute Force','Postfix SASL Auth Brute Force','Brute Force',
'Brute force sur authentification SASL Postfix.',
'SASL auth brute force on Postfix mail server.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 587 -j DROP',0,'Snort','TCP',587,NULL,'Commune'),

(20349,2001329,'API Key Brute Force','API Key Enumeration','Brute Force',
'Enumération de clés API par force brute — cible les apps web modernes.',
'API key enumeration by brute force.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(20350,2001330,'SSH Default Password','SSH Default Credentials','Brute Force',
'Tentative de connexion SSH avec identifiants par défaut (root/admin/admin).',
'SSH login attempt with default credentials.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 22 -j DROP',0,'Wazuh','TCP',22,NULL,'Très commune'),

(20351,2001331,'Kibana Brute Force','Kibana Dashboard Brute Force','Brute Force',
'Brute force sur tableau de bord Kibana/Wazuh.',
'Kibana/Wazuh dashboard brute force.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 5601 -j DROP',0,'Snort','TCP',5601,NULL,'Commune'),

(20352,2001332,'Grafana Brute Force','Grafana Brute Force','Brute Force',
'Brute force sur tableau de bord Grafana.',
'Grafana dashboard brute force.',
2,'Alerter',NULL,0,'Snort','TCP',3000,NULL,'Rare'),

(20353,2001333,'SNMP Community Brute Force','SNMP Community String Brute Force','Brute Force',
'Brute force community strings SNMP — accès configuration équipements réseau.',
'SNMP community string brute force.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 161 -j DROP',0,'Snort','UDP',161,NULL,'Commune'),

(20354,2001334,'RADIUS Brute Force','RADIUS Auth Brute Force','Brute Force',
'Brute force sur serveur RADIUS.',
'RADIUS authentication server brute force.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 1812 -j DROP',0,'Snort','UDP',1812,NULL,'Commune'),

(20355,2001335,'NFS Mount Brute Force','NFS Mount Brute Force','Brute Force',
'Tentatives de montage NFS non autorisées.',
'Unauthorized NFS mount attempts.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 2049 -j DROP',0,'Snort','TCP',2049,NULL,'Commune'),

(20356,2001336,'GitLab Brute Force','GitLab Brute Force','Brute Force',
'Brute force sur instance GitLab self-hosted.',
'Brute force on self-hosted GitLab.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(20357,2001337,'WinRM Brute Force','Windows Remote Management Brute Force','Brute Force',
'Brute force sur WinRM — mouvement latéral Windows.',
'WinRM brute force — Windows lateral movement.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 5985 -j DROP',0,'Snort','TCP',5985,NULL,'Commune'),

(20358,2001338,'Kubernetes API Brute Force','Kubernetes API Brute Force','Brute Force',
'Brute force sur API Kubernetes — infrastructure cloud.',
'Kubernetes API brute force — cloud infrastructure.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 6443 -j DROP',0,'Snort','TCP',6443,NULL,'Rare'),

(20359,2001339,'Drupal Login Brute Force','Drupal CMS Brute Force','Brute Force',
'Brute force sur CMS Drupal.',
'Drupal CMS brute force.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(20360,2001340,'Magento Admin Brute Force','Magento Admin Brute Force','Brute Force',
'Brute force sur admin Magento — boutiques en ligne africaines.',
'Magento admin brute force — African online shops.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

-- ================================================================
-- 2. RECONNAISSANCE — 50 entrées
-- ================================================================

(40101,1000001,'Scan Ports TCP SYN','TCP SYN Port Scan','Reconnaissance',
'Balayage de ports TCP en stealth scan. Première étape d une attaque — l attaquant cherche les services ouverts.',
'TCP SYN stealth port scan. First attack step — attacker looks for open services.',
2,'Alerter',NULL,0,'Snort','TCP',NULL,NULL,'Très commune'),

(40102,1000002,'Scan Ports UDP','UDP Port Scan','Reconnaissance',
'Balayage des ports UDP pour découvrir DNS, SNMP, DHCP.',
'UDP port scan to discover DNS, SNMP, DHCP services.',
2,'Alerter',NULL,0,'Snort','UDP',NULL,NULL,'Commune'),

(40103,1000003,'Nmap Détection OS','Nmap OS Detection','Reconnaissance',
'Empreinte OS par Nmap — l attaquant identifie le système cible.',
'OS fingerprinting by Nmap — attacker identifies target OS.',
2,'Alerter',NULL,0,'Snort','TCP',NULL,NULL,'Commune'),

(40104,1000004,'Nmap Scan Agressif','Nmap Aggressive Scan','Reconnaissance',
'Scan Nmap agressif — détection OS, services et scripts NSE.',
'Nmap aggressive scan — OS, services and NSE scripts.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(40105,1000005,'Ping Sweep ICMP','ICMP Ping Sweep','Reconnaissance',
'Envoi massif de pings ICMP pour découvrir les hôtes actifs.',
'Mass ICMP ping sweep to discover active hosts.',
1,'Observer',NULL,1,'Snort','ICMP',NULL,NULL,'Très commune'),

(40106,1000006,'Traceroute Détecté','Traceroute Detected','Reconnaissance',
'Traceroute pour cartographier la topologie réseau.',
'Traceroute to map network topology.',
1,'Observer',NULL,1,'Snort','ICMP',NULL,NULL,'Commune'),

(40107,1000007,'Nikto Web Scanner','Nikto Web Vulnerability Scan','Reconnaissance',
'Scanner Nikto — cherche des failles dans le serveur web.',
'Nikto scanner — looks for web server vulnerabilities.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(40108,1000008,'Masscan Scan Rapide','Masscan Port Scan','Reconnaissance',
'Scan réseau rapide Masscan — millions de ports en quelques secondes.',
'Fast Masscan network scan.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(40109,1000009,'SMB Énumération','SMB Share Enumeration','Reconnaissance',
'Énumération des partages SMB Windows — précède une attaque latérale.',
'Windows SMB share enumeration — precedes lateral attack.',
3,'Alerter',NULL,0,'Snort','TCP',445,NULL,'Commune'),

(40110,1000010,'SNMP Énumération','SNMP Enumeration','Reconnaissance',
'Requêtes SNMP pour extraire informations sur les équipements réseau.',
'SNMP queries to extract network device information.',
2,'Alerter',NULL,0,'Snort','UDP',161,NULL,'Commune'),

(40111,1000011,'DNS Zone Transfer','DNS Zone Transfer Attempt','Reconnaissance',
'Tentative de transfert de zone DNS — révèle toute l infrastructure.',
'DNS zone transfer attempt — reveals entire infrastructure.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 53 -j DROP',0,'Snort','TCP',53,NULL,'Commune'),

(40112,1000012,'DNS Énumération','DNS Enumeration','Reconnaissance',
'Énumération DNS agressive — sous-domaines, MX, NS.',
'Aggressive DNS enumeration — subdomains, MX, NS records.',
2,'Alerter',NULL,0,'Snort','UDP',53,NULL,'Commune'),

(40113,1000013,'Scan Port 80 HTTP','HTTP Port 80 Scan','Reconnaissance',
'Scan du port HTTP standard.',
'Standard HTTP port scan.',
1,'Observer',NULL,1,'Snort','TCP',80,NULL,'Très commune'),

(40114,1000014,'Scan Port 443 HTTPS','HTTPS Port 443 Scan','Reconnaissance',
'Scan du port HTTPS standard.',
'Standard HTTPS port scan.',
1,'Observer',NULL,1,'Snort','TCP',443,NULL,'Très commune'),

(40115,1000015,'Scan Port 22 SSH','SSH Port 22 Scan','Reconnaissance',
'Scan ciblé du port SSH.',
'Targeted SSH port scan.',
2,'Alerter',NULL,0,'Snort','TCP',22,NULL,'Très commune'),

(40116,1000016,'Scan Port 3389 RDP','RDP Port 3389 Scan','Reconnaissance',
'Scan du port bureau à distance Windows.',
'Windows Remote Desktop port scan.',
2,'Alerter',NULL,0,'Snort','TCP',3389,NULL,'Très commune'),

(40117,1000017,'Scan Port 3306 MySQL','MySQL Port 3306 Scan','Reconnaissance',
'Scan du port MySQL.',
'MySQL port scan.',
2,'Alerter',NULL,0,'Snort','TCP',3306,NULL,'Commune'),

(40118,1000018,'Scan Port 27017 MongoDB','MongoDB Port Scan','Reconnaissance',
'Scan du port MongoDB — base exposée sans auth en Afrique.',
'MongoDB port scan — often exposed without auth in Africa.',
3,'Alerter',NULL,0,'Snort','TCP',27017,NULL,'Très commune'),

(40119,1000019,'Scan Port 6379 Redis','Redis Port Scan','Reconnaissance',
'Scan du port Redis.',
'Redis port scan.',
3,'Alerter',NULL,0,'Snort','TCP',6379,NULL,'Très commune'),

(40120,1000020,'ARP Scan Réseau','ARP Network Scan','Reconnaissance',
'Scan ARP pour découvrir tous les hôtes sur le réseau local.',
'ARP scan to discover all hosts on LAN.',
2,'Alerter',NULL,1,'Snort','ARP',NULL,NULL,'Très commune'),

(40121,1000021,'WPScan WordPress','WordPress WPScan','Reconnaissance',
'Scanner WPScan — énumère les plugins et thèmes WordPress vulnérables.',
'WPScan — enumerates vulnerable WordPress plugins and themes.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(40122,1000022,'Dirbuster Directory Scan','Dirbuster Directory Brute Force','Reconnaissance',
'Dirbuster — énumère les répertoires et fichiers web cachés.',
'Dirbuster — enumerates hidden web directories and files.',
2,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(40123,1000023,'SQLMap Détecté','SQLMap Detection','Reconnaissance',
'Outil SQLMap détecté — injection SQL automatisée.',
'SQLMap detected — automated SQL injection tool.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(40124,1000024,'Metasploit Scanner','Metasploit Scanner Module','Reconnaissance',
'Module de scan Metasploit détecté.',
'Metasploit scan module detected.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(40125,1000025,'Burp Suite Scanner','Burp Suite Active Scanner','Reconnaissance',
'Scan actif Burp Suite — outil de pentest web.',
'Burp Suite active scan — web pentest tool.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(40126,1000026,'Acunetix Scanner','Acunetix Web Vulnerability Scanner','Reconnaissance',
'Scanner Acunetix — recherche de vulnérabilités web.',
'Acunetix scanner — web vulnerability search.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(40127,1000027,'Nuclei Scanner','Nuclei Vulnerability Scanner','Reconnaissance',
'Scanner Nuclei avec templates — détecte des centaines de vulnérabilités.',
'Nuclei scanner with templates — detects hundreds of vulnerabilities.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(40128,1000028,'Gobuster Dir Scan','Gobuster Directory Scan','Reconnaissance',
'Scan Gobuster — énumération de répertoires et fichiers web.',
'Gobuster scan — web directories and files enumeration.',
2,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(40129,1000029,'Enum4linux Windows','Enum4linux Windows Enumeration','Reconnaissance',
'Outil enum4linux pour énumération Windows/Samba.',
'Enum4linux for Windows/Samba enumeration.',
3,'Alerter',NULL,0,'Snort','TCP',445,NULL,'Commune'),

(40130,1000030,'Shodan Bot Scan','Shodan Internet Scan','Reconnaissance',
'Scan automatisé type Shodan — cartographie services exposés.',
'Shodan-type automated scan — maps exposed services.',
2,'Alerter',NULL,1,'Snort','TCP',NULL,NULL,'Très commune'),

(40131,1000031,'SSL TLS Fingerprinting','SSL TLS Fingerprinting','Reconnaissance',
'Analyse empreinte SSL/TLS — identifie versions vulnérables.',
'SSL/TLS fingerprinting — identifies vulnerable versions.',
2,'Alerter',NULL,1,'Snort','TCP',443,NULL,'Commune'),

(40132,1000032,'Hping3 Scan','Hping3 Network Scan','Reconnaissance',
'Outil hping3 — scans réseau avancés et tests de DoS.',
'Hping3 tool — advanced network scans and DoS tests.',
3,'Alerter',NULL,0,'Snort','TCP',NULL,NULL,'Commune'),

(40133,1000033,'WAF Detection Probe','WAF Detection Probe','Reconnaissance',
'Sondes pour détecter et identifier le type de WAF utilisé.',
'Probes to detect and identify WAF type.',
2,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(40134,1000034,'Scan Ports IoT','IoT Device Port Scan','Reconnaissance',
'Scan ports IoT (Telnet, UPnP, RTSP) — cible caméras et routeurs.',
'IoT device port scan — targets cameras and routers.',
2,'Alerter',NULL,0,'Snort','TCP',NULL,NULL,'Commune'),

(40135,1000035,'Sonde EternalBlue 445','EternalBlue Port 445 Probe','Reconnaissance',
'Scan port 445 avec sonde EternalBlue — précède une attaque ransomware.',
'Port 445 scan with EternalBlue probe — precedes ransomware attack.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 445 -j DROP',0,'Snort','TCP',445,'CVE-2017-0144','Commune'),

(40136,1000036,'Banner Grabbing','Service Banner Grabbing','Reconnaissance',
'Récupération des bannières pour identifier les versions logicielles.',
'Banner grabbing to identify software versions.',
1,'Observer',NULL,0,'Snort','TCP',NULL,NULL,'Très commune'),

(40137,1000037,'HTTP OPTIONS Scan','HTTP OPTIONS Method Scan','Reconnaissance',
'Méthode HTTP OPTIONS pour identifier les méthodes supportées.',
'HTTP OPTIONS to identify supported methods.',
1,'Observer',NULL,1,'Snort','TCP',80,NULL,'Commune'),

(40138,1000038,'Scan RPC Services','RPC Services Scan','Reconnaissance',
'Énumération des services RPC exposés.',
'RPC services enumeration.',
2,'Alerter',NULL,0,'Snort','TCP',111,NULL,'Commune'),

(40139,1000039,'Scan TFTP','TFTP Service Scan','Reconnaissance',
'Scan TFTP — configurations équipements réseau volables.',
'TFTP scan — network device configurations can be stolen.',
2,'Alerter',NULL,0,'Snort','UDP',69,NULL,'Commune'),

(40140,1000040,'Scan Infrastructure Cloud','Cloud Infrastructure Scan','Reconnaissance',
'Scan des endpoints cloud (AWS, Azure metadata) — peut révéler des credentials.',
'Cloud endpoints scan — can reveal credentials.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(40141,1000041,'OpenVAS Scan','OpenVAS Vulnerability Scan','Reconnaissance',
'Scanner OpenVAS détecté — peut être légitime ou malveillant.',
'OpenVAS scanner detected — can be legitimate or malicious.',
2,'Alerter',NULL,1,'Snort','TCP',NULL,NULL,'Commune'),

(40142,1000042,'Scan Port 9200 Elasticsearch','Elasticsearch Port Scan','Reconnaissance',
'Scan port Elasticsearch — données souvent non protégées.',
'Elasticsearch port scan — data often unprotected.',
2,'Alerter',NULL,0,'Snort','TCP',9200,NULL,'Commune'),

(40143,1000043,'Fimap LFI RFI Scanner','Fimap LFI RFI Scanner','Reconnaissance',
'Scanner Fimap — recherche automatique de vulnérabilités LFI/RFI.',
'Fimap scanner — automatic LFI/RFI vulnerability finder.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(40144,1000044,'Subfinder Subdomain Enum','Subfinder Subdomain Enumeration','Reconnaissance',
'Énumération automatique des sous-domaines.',
'Automatic subdomain enumeration.',
2,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(40145,1000045,'HTTP PUT Method Scan','HTTP PUT Method Abuse','Reconnaissance',
'Méthode HTTP PUT pour tenter d uploader des fichiers.',
'HTTP PUT method to attempt file upload.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(40146,1000046,'CORS Misconfiguration Probe','CORS Misconfiguration Probe','Reconnaissance',
'Sonde mauvaise configuration CORS — fuites cross-origin.',
'CORS misconfiguration probe — cross-origin data leaks.',
2,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(40147,1000047,'LDAP Enumeration','LDAP Active Directory Enumeration','Reconnaissance',
'Énumération LDAP/AD — utilisateurs et groupes.',
'LDAP/AD enumeration — users and groups.',
3,'Alerter',NULL,0,'Snort','TCP',389,NULL,'Commune'),

(40148,1000048,'Scan Port 8080 Tomcat','Apache Tomcat Port Scan','Reconnaissance',
'Scan ciblé port Tomcat 8080 — précède une attaque Tomcat Manager.',
'Targeted Tomcat port 8080 scan.',
2,'Alerter',NULL,0,'Snort','TCP',8080,NULL,'Commune'),

(40149,1000049,'NetBIOS Enumeration','NetBIOS Enumeration','Reconnaissance',
'Requêtes NetBIOS pour découvrir machines Windows sur réseau local.',
'NetBIOS queries to discover Windows machines on LAN.',
2,'Alerter',NULL,1,'Snort','UDP',137,NULL,'Commune'),

(40150,1000050,'Scan Shodan-Like Automation','Automated Internet Scanner','Reconnaissance',
'Scanner internet automatisé similaire à Shodan ou Censys.',
'Automated internet scanner similar to Shodan or Censys.',
1,'Observer',NULL,1,'Snort','TCP',NULL,NULL,'Très commune'),

-- ================================================================
-- 3. WEB ATTACK — 60 entrées
-- ================================================================

(31103,2006445,'SQL Injection','SQL Injection','Web Attack',
'Injection SQL dans les paramètres d une application web — exfiltration ou modification de données.',
'SQL injection in web application parameters.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(31104,2006446,'SQL Injection Aveugle','Blind SQL Injection','Web Attack',
'Injection SQL aveugle — l attaquant infère des données sans affichage d erreurs.',
'Blind SQL injection — attacker infers data without error display.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31105,2006447,'SQL Injection Union','Union Based SQL Injection','Web Attack',
'Injection SQL avec clause UNION pour extraire des données.',
'SQL injection with UNION to extract data.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31106,2006448,'SQL Injection Time Based','Time Based Blind SQL Injection','Web Attack',
'Injection SQL temporelle — l attaquant infère des données via des délais.',
'Time-based blind SQL injection via response delays.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31107,2006449,'SQL Injection Error Based','Error Based SQL Injection','Web Attack',
'Injection SQL basée sur les messages d erreur de la base.',
'Error-based SQL injection using database error messages.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31110,2006450,'XSS Réfléchi','Reflected XSS','Web Attack',
'Cross-Site Scripting réfléchi — injection JavaScript malveillant dans la réponse.',
'Reflected XSS — malicious JavaScript injection in response.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(31111,2006451,'XSS Stocké','Stored XSS','Web Attack',
'XSS persistant stocké en base — affecte tous les visiteurs de la page.',
'Persistent XSS stored in database — affects all page visitors.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31112,2006452,'XSS DOM Based','DOM Based XSS','Web Attack',
'XSS basé sur le DOM — manipulation du Document Object Model.',
'DOM-based XSS — Document Object Model manipulation.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31120,2006460,'LFI Local File Inclusion','Local File Inclusion','Web Attack',
'Inclusion de fichiers locaux — expose /etc/passwd et fichiers de configuration.',
'Local file inclusion — exposes /etc/passwd and config files.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31121,2006461,'RFI Remote File Inclusion','Remote File Inclusion','Web Attack',
'Inclusion d un fichier distant malveillant — peut mener à RCE.',
'Remote malicious file inclusion — can lead to RCE.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31130,2006470,'CSRF Cross Site Request Forgery','CSRF Attack','Web Attack',
'Falsification de requête cross-site — force l utilisateur à exécuter des actions non désirées.',
'Cross-site request forgery — forces user to execute unwanted actions.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31140,2006480,'Traversée Répertoire','Directory Traversal','Web Attack',
'Accès à des fichiers hors du répertoire web via ../.',
'Access to files outside web directory via ../.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31141,2006481,'Accès htaccess','Htaccess Access Attempt','Web Attack',
'Tentative d accès au fichier .htaccess d Apache.',
'Attempt to access Apache .htaccess file.',
2,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31150,2006490,'PHP Code Injection','PHP Code Injection','Web Attack',
'Injection de code PHP — exécution de commandes système possible.',
'PHP code injection — system command execution possible.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31151,2006491,'Command Injection OS','OS Command Injection','Web Attack',
'Injection de commandes OS via paramètres web non filtrés.',
'OS command injection via unfiltered web parameters.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31160,2006500,'Upload Fichier Malveillant','Malicious File Upload','Web Attack',
'Upload d un fichier .php, .asp, .exe — création de webshell possible.',
'Upload of .php, .asp, .exe file — webshell creation possible.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(31161,2006501,'Webshell Détecté','Webshell Detected','Web Attack',
'Webshell PHP/ASP — porte dérobée donnant contrôle total du serveur.',
'PHP/ASP webshell — backdoor giving full server control.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31170,2006510,'SSRF Server Side Request Forgery','SSRF Attack','Web Attack',
'Falsification requête côté serveur — accès aux ressources internes non exposées.',
'Server-side request forgery — access to unexposed internal resources.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2024-2121','Commune'),

(31180,2006520,'XXE XML External Entity','XXE Injection','Web Attack',
'Injection d entité XML externe — lit des fichiers système ou SSRF.',
'XML external entity injection — reads system files or performs SSRF.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Rare'),

(31190,2006530,'IDOR Accès Non Autorisé','IDOR Attack','Web Attack',
'Référence directe objet non autorisée — accès données d autres utilisateurs.',
'Insecure direct object reference — access to other users data.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31200,2006540,'Open Redirect','Open Redirect Attack','Web Attack',
'Redirection ouverte vers un site malveillant — utilisée en phishing.',
'Open redirect to malicious site — used in phishing.',
2,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31210,2006550,'HTTP Request Smuggling','HTTP Request Smuggling','Web Attack',
'Contrebande de requêtes HTTP — différences d interprétation proxy/serveur.',
'HTTP request smuggling — proxy/server interpretation differences.',
4,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31220,2006560,'NoSQL Injection MongoDB','NoSQL MongoDB Injection','Web Attack',
'Injection dans opérateurs MongoDB — fréquent sur applications Node.js.',
'NoSQL injection in MongoDB operators — common on Node.js apps.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31230,2006570,'Log4Shell JNDI Injection','Log4j JNDI Injection','Web Attack',
'Injection JNDI dans Log4j — une des failles les plus exploitées.',
'Log4j JNDI injection — one of the most exploited vulnerabilities.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,'CVE-2021-44228','Commune'),

(31240,2006580,'SSTI Template Injection','Server Side Template Injection','Web Attack',
'Injection dans un moteur de template côté serveur — RCE possible.',
'Server-side template injection — RCE possible.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31250,2006590,'JWT Manipulation','JWT Token Manipulation','Web Attack',
'Manipulation de token JWT pour usurper une identité.',
'JWT token manipulation for identity spoofing.',
4,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(31260,2006600,'Deserialization Java','Java Deserialization RCE','Web Attack',
'Désérialisation Java non sécurisée — exécution de code arbitraire.',
'Unsafe Java deserialization — arbitrary code execution.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(31270,2006610,'WordPress Plugin RCE','WordPress Plugin RCE','Web Attack',
'Exploitation d un plugin WordPress vulnérable — RCE très fréquent.',
'Vulnerable WordPress plugin exploitation — very frequent RCE.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(31280,2006620,'PrestaShop SQL Injection','PrestaShop SQL Injection','Web Attack',
'Injection SQL dans PrestaShop — boutiques africaines ciblées.',
'SQL injection in PrestaShop — African shops targeted.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2023-30839','Commune'),

(31290,2006630,'Jenkins Groovy RCE','Jenkins Groovy Console RCE','Web Attack',
'Scripts Groovy via console Jenkins — RCE total sur le serveur.',
'Groovy scripts via Jenkins console — full server RCE.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 8080 -j DROP',0,'Snort','TCP',8080,NULL,'Commune'),

(31300,2006640,'Confluence RCE','Atlassian Confluence RCE','Web Attack',
'Exploitation RCE dans Atlassian Confluence.',
'RCE in Atlassian Confluence.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',8090,'CVE-2022-26134','Commune'),

(31310,2006650,'PHP Object Injection','PHP Object Injection','Web Attack',
'Injection d objet PHP via désérialisation — RCE possible.',
'PHP object injection via deserialization — RCE possible.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31320,2006660,'Cache Poisoning Web','Web Cache Poisoning','Web Attack',
'Empoisonnement du cache web — contenu malveillant servi à tous.',
'Web cache poisoning — malicious content served to all users.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Rare'),

(31330,2006670,'Host Header Injection','Host Header Injection','Web Attack',
'Injection dans le header Host HTTP — peut mener à SSRF.',
'Host header injection — can lead to SSRF.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31340,2006680,'SMTP Header Injection','SMTP Header Injection','Web Attack',
'Injection dans les headers SMTP — envoi de spam depuis le serveur.',
'SMTP header injection — spam sending from server.',
2,'Alerter',NULL,0,'Snort','TCP',25,NULL,'Commune'),

(31350,2006690,'Image Upload Webshell','Malicious Image Upload Webshell','Web Attack',
'Webshell caché dans une image uploadée — contourne les filtres d extension.',
'Webshell hidden in uploaded image — bypasses extension filters.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(31360,2006700,'LDAP Injection','LDAP Injection','Web Attack',
'Injection LDAP — contournement authentification ou exfiltration.',
'LDAP injection — authentication bypass or exfiltration.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 389 -j DROP',0,'Snort','TCP',389,NULL,'Commune'),

(31370,2006710,'GraphQL Injection','GraphQL Injection Attack','Web Attack',
'Injection dans API GraphQL — extraction non autorisée de données.',
'GraphQL API injection — unauthorized data extraction.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31380,2006720,'Mass Assignment','Mass Assignment Vulnerability','Web Attack',
'Mauvaise restriction d affectation de masse dans une API REST.',
'Mass assignment exploitation in REST API.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31390,2006730,'ImageMagick RCE','ImageMagick ImageTragick RCE','Web Attack',
'ImageTragick dans ImageMagick — RCE via images malformées uploadées.',
'ImageTragick in ImageMagick — RCE via malformed uploaded images.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2016-3714','Commune'),

(31400,2006740,'CSV Formula Injection','CSV Formula Injection','Web Attack',
'Formules injectées dans des exports CSV — exécution à l ouverture.',
'Formula injection in CSV exports — execution on file open.',
2,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31410,2006750,'Nginx Path Traversal','Nginx Path Traversal','Web Attack',
'Traversée de chemin dans Nginx.',
'Path traversal in Nginx.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2021-23017','Commune'),

(31420,2006760,'Spring4Shell RCE','Spring4Shell RCE','Web Attack',
'Exploitation Spring4Shell dans Spring Framework.',
'Spring4Shell exploitation in Spring Framework.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',80,'CVE-2022-22965','Commune'),

(31430,2006770,'WebSocket Hijacking','WebSocket Cross-Site Hijacking','Web Attack',
'Détournement de connexion WebSocket cross-origin.',
'Cross-origin WebSocket connection hijacking.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31440,2006780,'Broken Object Level Auth','BOLA IDOR API Attack','Web Attack',
'Autorisation objet cassée — accès données autres utilisateurs via API.',
'Broken object level authorization — other users data via API.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(31450,2006790,'API Rate Limit Bypass','API Rate Limiting Bypass','Web Attack',
'Contournement des limites de débit API.',
'API rate limit bypass.',
2,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(31460,2006800,'GitLab Path Traversal RCE','GitLab Path Traversal RCE','Web Attack',
'Traversée de chemin et RCE dans GitLab Community Edition.',
'Path traversal and RCE in GitLab CE.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2021-22205','Commune'),

(31470,2006810,'Zip Slip Traversal','Zip Slip Path Traversal','Web Attack',
'Extraction ZIP avec chemin malveillant — écrase des fichiers système.',
'ZIP extraction with malicious path — overwrites system files.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31480,2006820,'SAML Auth Bypass','SAML Authentication Bypass','Web Attack',
'Manipulation des assertions SAML — contourne l authentification SSO.',
'SAML assertion manipulation — bypasses SSO authentication.',
4,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Rare'),

(31490,2006830,'JWT None Algorithm','JWT None Algorithm Attack','Web Attack',
'Exploitation algorithme "none" dans JWT — forge des tokens valides.',
'JWT "none" algorithm exploitation — forges valid tokens.',
4,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(31500,2006840,'MOVEit Transfer SQLi','MOVEit Transfer SQL Injection','Web Attack',
'Injection SQL critique dans MOVEit Transfer.',
'Critical SQL injection in MOVEit Transfer.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2023-34362','Commune'),

-- ================================================================
-- 4. DOS / DDOS — 30 entrées
-- ================================================================

(1000100,2100001,'SYN Flood','TCP SYN Flood','DoS',
'Inondation SYN TCP — sature la table des connexions du serveur.',
'TCP SYN flood — saturates server connection table.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --syn -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(1000101,2100002,'UDP Flood','UDP Flood','DDoS',
'Inondation UDP saturant la bande passante.',
'UDP flood saturating bandwidth.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p udp -j DROP',0,'Snort','UDP',NULL,NULL,'Commune'),

(1000102,2100003,'ICMP Flood','ICMP Flood','DoS',
'Inondation ICMP saturant bande passante et CPU.',
'ICMP flood saturating bandwidth and CPU.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p icmp -j DROP',0,'Snort','ICMP',NULL,NULL,'Commune'),

(1000103,2100004,'HTTP Flood DDoS','HTTP Flood DDoS','DDoS',
'Inondation HTTP simulant des milliers de requêtes légitimes.',
'HTTP flood simulating thousands of legitimate requests.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(1000104,2100005,'DNS Amplification DDoS','DNS Amplification DDoS','DDoS',
'Amplification DDoS via serveurs DNS ouverts — très utilisée en Afrique.',
'DDoS amplification via open DNS servers — widely used in Africa.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 53 -j DROP',0,'Snort','UDP',53,NULL,'Très commune'),

(1000105,2100006,'NTP Amplification DDoS','NTP Amplification Attack','DDoS',
'Amplification DDoS via NTP — facteur d amplification jusqu à 500x.',
'NTP DDoS amplification — factor up to 500x.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 123 -j DROP',0,'Snort','UDP',123,NULL,'Commune'),

(1000106,2100007,'Slowloris Attack','Slowloris HTTP Attack','DoS',
'Connexions HTTP partielles maintenues — épuise les connexions du serveur.',
'Partial HTTP connections — exhausts server connections.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(1000107,2100008,'RUDY Slow POST','RUDY Slow POST Attack','DoS',
'Requêtes POST envoyées très lentement — bloque les threads du serveur.',
'POST requests sent very slowly — blocks server threads.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Rare'),

(1000108,2100009,'Botnet DDoS Détecté','Botnet DDoS Detected','DDoS',
'Trafic botnet DDoS — attaque coordonnée depuis machines infectées.',
'Botnet DDoS traffic — coordinated attack from infected machines.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(1000109,2100010,'Memcached Amplification','Memcached DDoS Amplification','DDoS',
'Amplification DDoS via Memcached — facteur 51000x.',
'Memcached DDoS amplification — 51000x factor.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 11211 -j DROP',0,'Snort','UDP',11211,NULL,'Commune'),

(1000110,2100011,'Smurf Attack','Smurf ICMP Amplification','DDoS',
'Attaque Smurf — amplification ICMP via broadcast.',
'Smurf attack — ICMP amplification via broadcast.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p icmp -j DROP',0,'Snort','ICMP',NULL,NULL,'Rare'),

(1000111,2100012,'DNS Water Torture','DNS Water Torture DDoS','DDoS',
'Attaque DNS par requêtes de sous-domaines aléatoires — sature le serveur.',
'DNS water torture — random subdomain queries saturate server.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p udp --dport 53 -j DROP',0,'Snort','UDP',53,NULL,'Commune'),

(1000112,2100013,'HTTP GET Flood','HTTP GET Flood DDoS','DDoS',
'Inondation de requêtes HTTP GET simples mais en grand volume.',
'Simple HTTP GET requests in high volume.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(1000113,2100014,'HTTPS DDoS','HTTPS SSL DDoS Attack','DDoS',
'DDoS sur HTTPS — le chiffrement SSL amplifie la charge CPU.',
'HTTPS DDoS — SSL encryption amplifies CPU load.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,NULL,'Commune'),

(1000114,2100015,'API DDoS','API Endpoint DDoS Attack','DDoS',
'DDoS ciblant des endpoints API spécifiques.',
'DDoS targeting specific API endpoints.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,NULL,'Commune'),

-- ================================================================
-- 5. RANSOMWARE — 30 entrées
-- Menace #1 PME africaines selon INTERPOL 2025
-- ================================================================

(60001,2030001,'LockBit Communication C2','LockBit C2 Communication','Ransomware',
'Communication LockBit C2 — ransomware le plus actif en Afrique du Sud et Égypte.',
'LockBit C2 communication — most active ransomware in South Africa and Egypt.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(60002,2030002,'GhostLocker Ransomware','GhostLocker Ransomware','Ransomware',
'GhostLocker 2.0 — utilisé par GhostSec en double-extorsion contre cibles africaines.',
'GhostLocker 2.0 — used by GhostSec in double-extortion against African targets.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(60003,2030003,'Chiffrement Massif Fichiers','Mass File Encryption','Ransomware',
'Activité de chiffrement massif détectée — ransomware potentiellement actif.',
'Mass file encryption activity — ransomware potentially active.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Commune'),

(60004,2030004,'Note de Rançon Créée','Ransom Note Created','Ransomware',
'Fichier README.txt ou DECRYPT_FILES créé — signature typique ransomware.',
'README.txt or DECRYPT_FILES created — typical ransomware signature.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Commune'),

(60005,2030005,'Suppression Shadow Copies','Shadow Copy Deletion','Ransomware',
'Suppression vssadmin des copies shadow — empêche la récupération.',
'vssadmin shadow copy deletion — prevents recovery.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Commune'),

(60006,2030006,'Extension Fichiers Chiffrés','Encrypted File Extension','Ransomware',
'Fichiers avec extensions .locked, .encrypted, .enc détectés.',
'Files with .locked, .encrypted, .enc extensions detected.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Commune'),

(60007,2030007,'Dharma Ransomware','Dharma CrySiS Ransomware','Ransomware',
'Dharma — ransomware très répandu ciblant les PME via RDP exposé.',
'Dharma ransomware targeting SMEs via exposed RDP.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(60008,2030008,'STOP Djvu Ransomware','STOP Djvu Ransomware','Ransomware',
'STOP/Djvu — ransomware le plus répandu, distribué via cracks logiciels.',
'STOP/Djvu most widespread ransomware — distributed via software cracks.',
3,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(60009,2030009,'Conti Ransomware','Conti Ransomware','Ransomware',
'Conti — groupe ransomware ayant ciblé des gouvernements africains.',
'Conti — ransomware group targeting African governments.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(60010,2030010,'LockBit 3.0 BlackCat','LockBit 3.0 BlackCat Ransomware','Ransomware',
'LockBit 3.0 / BlackCat — variantes modernes très difficiles à détecter.',
'LockBit 3.0 / BlackCat — modern variants very difficult to detect.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(60011,2030011,'Hunters International Ransomware','Hunters International','Ransomware',
'Hunters International — a attaqué Telecom Namibia décembre 2024.',
'Hunters International — attacked Telecom Namibia December 2024.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Custom','TCP',NULL,NULL,'Commune'),

(60012,2030012,'Medusa Ransomware','Medusa Ransomware','Ransomware',
'Medusa — actif en Afrique du Sud et Est. Double extorsion.',
'Medusa — active in South Africa and East Africa.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Custom','TCP',NULL,NULL,'Commune'),

(60013,2030013,'Phobos Ransomware','Phobos Ransomware','Ransomware',
'Phobos — similaire à Dharma, cible les RDP exposés.',
'Phobos ransomware — similar to Dharma, targets exposed RDP.',
3,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(60014,2030014,'RaaS Communication C2','RaaS C2 Connection','Ransomware',
'Connexion à une infrastructure Ransomware-as-a-Service détectée.',
'RaaS infrastructure connection detected.',
4,'Isoler machine','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(60015,2030015,'Ransomware Linux ESXi','Linux ESXi Ransomware','Ransomware',
'Ransomware ciblant serveurs ESXi Linux pour chiffrer les VMs.',
'Ransomware targeting ESXi Linux to encrypt business VMs.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Custom','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- 6. MALWARE / CRYPTO — 30 entrées
-- ================================================================

(70001,2040001,'Trojan HTTP C2','Trojan HTTP C2','Malware',
'Communication d un trojan avec son serveur C2 via HTTP.',
'Trojan communication with C2 server via HTTP.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',80,NULL,'Commune'),

(70002,2040002,'Trojan HTTPS C2','Trojan HTTPS C2','Malware',
'Communication chiffrée d un trojan avec son C2.',
'Encrypted trojan communication with C2.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',443,NULL,'Commune'),

(70010,2040010,'Emotet Trojan Bancaire','Emotet Banking Trojan','Malware',
'Emotet — trojan bancaire très actif utilisé pour déployer ransomwares.',
'Emotet banking trojan — used to deploy ransomware.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(70011,2040011,'Agent Tesla Keylogger','Agent Tesla Keylogger','Malware',
'Agent Tesla — enregistre frappes clavier, mots de passe, données bancaires.',
'Agent Tesla — records keystrokes, passwords, banking data.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(70012,2040012,'Remcos RAT','Remcos Remote Access Trojan','Malware',
'Remcos RAT — contrôle complet à distance, diffusé via phishing en Afrique.',
'Remcos RAT — full remote control, distributed via phishing in Africa.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(70013,2040013,'Lumma Stealer','Lumma Information Stealer','Malware',
'Lumma Stealer — vole navigateurs, portefeuilles crypto et données FTP.',
'Lumma Stealer — steals browsers, crypto wallets and FTP data.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(70014,2040014,'RedLine Stealer','RedLine Information Stealer','Malware',
'RedLine — vole mots de passe, cookies et données bancaires.',
'RedLine — steals passwords, cookies and banking data.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(70015,2040015,'njRAT Afrique','njRAT Remote Access Trojan','Malware',
'njRAT — RAT populaire en Afrique du Nord et Moyen-Orient.',
'njRAT popular in North Africa and Middle East.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(70016,2040016,'DarkComet RAT','DarkComet Remote Access Trojan','Malware',
'DarkComet — outil de surveillance distribué en Afrique subsaharienne.',
'DarkComet surveillance tool distributed in sub-Saharan Africa.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

(70017,2040017,'AsyncRAT','AsyncRAT Detection','Malware',
'AsyncRAT — trojan open source pour surveillance et vol de données.',
'AsyncRAT open source trojan for surveillance and data theft.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(70018,2040018,'QuasarRAT','QuasarRAT Open Source RAT','Malware',
'QuasarRAT — RAT open source ciblant des PME africaines.',
'QuasarRAT open source RAT targeting African SMEs.',
3,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(70019,2040019,'Qakbot Banking Trojan','Qakbot Banking Trojan','Malware',
'Qakbot — trojan bancaire et loader pour déployer des ransomwares.',
'Qakbot banking trojan and ransomware loader.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(70020,2040020,'Mirai Botnet','Mirai Botnet Infection','Malware',
'Mirai — infecte équipements IoT pour lancer des DDoS.',
'Mirai — infects IoT devices to launch DDoS.',
4,'Isoler machine','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(70030,2040030,'Cryptominer Non Autorisé','Unauthorized Cryptominer','Crypto',
'Processus de minage non autorisé — consomme les ressources CPU.',
'Unauthorized mining process — consumes CPU resources.',
3,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(70031,2040031,'XMRig Monero Miner','XMRig Monero Miner','Crypto',
'XMRig — très répandu sur les serveurs africains compromis.',
'XMRig — very common on compromised African servers.',
3,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(70040,2040040,'Backdoor Détecté','Backdoor Detected','Malware',
'Porte dérobée — accès persistant pour l attaquant.',
'Backdoor — persistent access for attacker.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(70041,2040041,'Rootkit Détecté','Rootkit Detected','Malware',
'Rootkit — malware masquant sa présence dans le système.',
'Rootkit — malware hiding its presence.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(70042,2040042,'Fileless Malware','Fileless Malware Execution','Malware',
'Malware sans fichier — s exécute directement en mémoire.',
'Fileless malware — executes directly in memory.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(70043,2040043,'PlugX APT Backdoor','PlugX Remote Access Tool','Malware',
'PlugX — utilisé par des groupes APT ciblant des gouvernements africains.',
'PlugX — used by APT groups targeting African governments.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(70044,2040044,'GuLoader Dropper','GuLoader Malware Dropper','Malware',
'GuLoader — télécharge des malwares depuis des services cloud légitimes.',
'GuLoader — downloads malware from legitimate cloud services.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Très commune'),

-- ================================================================
-- 7. PHISHING / BEC — 30 entrées
-- Menace #1 en volume selon INTERPOL Afrique 2025
-- ================================================================

(80001,2050001,'Email Spoofing Phishing','Email Spoofing Phishing','Phishing',
'Email avec adresse expéditeur usurpée — phishing très fréquent contre PME africaines.',
'Email with spoofed sender — frequent phishing against African SMEs.',
3,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80002,2050002,'Lien Malveillant Email','Malicious URL in Email','Phishing',
'URL malveillante dans un email — redirige vers vol de credentials.',
'Malicious URL in email — redirects to credential theft.',
3,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80003,2050003,'Business Email Compromise','Business Email Compromise','BEC',
'Compromission messagerie professionnelle — arnaque très lucrative ciblant virements.',
'Business email compromise — very lucrative scam targeting wire transfers.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80004,2050004,'BEC Usurpation PDG','CEO Fraud BEC','BEC',
'Email usurpant le PDG pour demander un virement urgent.',
'Email impersonating CEO requesting urgent wire transfer.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80005,2050005,'BEC Usurpation Fournisseur','BEC Vendor Impersonation','BEC',
'Usurpation fournisseur pour détourner des paiements.',
'Vendor impersonation to divert payments.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80006,2050006,'Mobile Money Phishing','Mobile Money Phishing','Phishing',
'Phishing ciblant Mobile Money — Orange Money, Wave, MTN MoMo, M-Pesa.',
'Phishing targeting Mobile Money — Orange Money, Wave, MTN MoMo.',
4,'Alerter',NULL,0,'Wazuh','TCP',80,NULL,'Très commune'),

(80007,2050007,'Phishing Banque Africaine','African Bank Phishing','Phishing',
'Phishing imitant une banque africaine — Ecobank, UBA, Equity Bank, ABSA.',
'Phishing impersonating African bank — Ecobank, UBA, Equity Bank, ABSA.',
4,'Alerter',NULL,0,'Wazuh','TCP',80,NULL,'Très commune'),

(80008,2050008,'Orange Money Phishing','Orange Money Phishing','Phishing',
'Phishing Orange Money — service très utilisé en Afrique de l Ouest et Centrale.',
'Orange Money phishing — widely used in West and Central Africa.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Très commune'),

(80009,2050009,'Wave Money Phishing','Wave Money Phishing','Phishing',
'Phishing Wave — service dominant de transfert d argent en Afrique de l Ouest.',
'Wave phishing — dominant money transfer service in West Africa.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Très commune'),

(80010,2050010,'MTN MoMo Phishing','MTN Mobile Money Phishing','Phishing',
'Phishing MTN Mobile Money — présent dans 16 pays africains.',
'MTN Mobile Money phishing — present in 16 African countries.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Très commune'),

(80011,2050011,'M-Pesa Phishing','M-Pesa Phishing','Phishing',
'Phishing M-Pesa — plateforme dominante Kenya et Afrique de l Est.',
'M-Pesa phishing — dominant platform in Kenya and East Africa.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Commune'),

(80012,2050012,'Phishing Microsoft 365','Microsoft 365 Phishing','Phishing',
'Phishing imitant Microsoft 365 — vole identifiants professionnels.',
'Microsoft 365 phishing — steals professional credentials.',
4,'Alerter',NULL,0,'Wazuh','TCP',443,NULL,'Très commune'),

(80013,2050013,'Phishing Google Workspace','Google Workspace Phishing','Phishing',
'Phishing Google Workspace — vol de compte Google professionnel.',
'Google Workspace phishing — professional Google account theft.',
3,'Alerter',NULL,0,'Wazuh','TCP',443,NULL,'Très commune'),

(80014,2050014,'BEC Masse Salariale','BEC Payroll Diversion','BEC',
'Compromission email pour détourner la masse salariale.',
'Email compromise to divert payroll.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80015,2050015,'Arnaque 419 Advance Fee','Nigerian Prince 419 Fraud','Phishing',
'Fraude aux frais avancés — toujours active et coûteuse en Afrique.',
'Advance fee fraud — still active and costly in Africa.',
3,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(80016,2050016,'Spear Phishing Ciblé','Targeted Spear Phishing','Phishing',
'Phishing personnalisé utilisant informations spécifiques à la cible.',
'Personalized phishing using target-specific information.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Très commune'),

(80017,2050017,'Romance Scam Pig Butchering','Romance Scam Investment Fraud','Phishing',
'Arnaque sentimentale avec investissement crypto — identifiée par INTERPOL Afrique 2025.',
'Romance scam with crypto investment — identified by INTERPOL Africa 2025.',
3,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(80018,2050018,'Phishing DHL Express','DHL Express Phishing','Phishing',
'Phishing imitant DHL Express — vol d informations bancaires.',
'DHL Express phishing — banking information theft.',
3,'Alerter',NULL,0,'Wazuh','TCP',80,NULL,'Très commune'),

(80019,2050019,'Phishing Service Douanes','Customs Service Phishing','Phishing',
'Phishing imitant les douanes africaines — paiement de droits fictifs.',
'Customs service phishing — fictitious duties payment.',
3,'Alerter',NULL,0,'Wazuh','TCP',80,NULL,'Très commune'),

(80020,2050020,'Whaling Ciblage Direction','Whaling Executive Targeting','Phishing',
'Phishing ciblant les dirigeants PDG, CFO — montants très élevés.',
'Phishing targeting executives CEO, CFO — very high amounts.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Commune'),

-- ================================================================
-- 8. INTRUSION / EXPLOITATION — 30 entrées
-- ================================================================

(1100001,2060001,'EternalBlue MS17-010','EternalBlue MS17-010','Intrusion',
'Exploit EternalBlue ciblant SMBv1 — utilisé par WannaCry et NotPetya.',
'EternalBlue targeting SMBv1 — used by WannaCry and NotPetya.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 445 -j DROP',0,'Snort','TCP',445,'CVE-2017-0144','Commune'),

(1100002,2060002,'Log4Shell RCE','Log4Shell Remote Code Execution','Intrusion',
'Exploitation Log4Shell — exécution de code à distance critique.',
'Log4Shell exploitation — critical remote code execution.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,'CVE-2021-44228','Commune'),

(1100003,2060003,'Shellshock Bash RCE','Shellshock Bash Vulnerability','Intrusion',
'Exploitation Shellshock dans Bash — présent sur serveurs Linux anciens.',
'Shellshock Bash vulnerability — present on old Linux servers.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',NULL,'CVE-2014-6271','Commune'),

(1100004,2060004,'ProxyLogon Exchange RCE','ProxyLogon Exchange','Intrusion',
'ProxyLogon — accès sans authentification au serveur Exchange.',
'ProxyLogon — unauthenticated Exchange server access.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,'CVE-2021-26855','Commune'),

(1100005,2060005,'SMB Exploitation','SMB Protocol Exploitation','Intrusion',
'Exploitation du protocole SMB — vecteur d attaque principal sur réseaux Windows.',
'SMB protocol exploitation — main attack vector on Windows networks.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 445 -j DROP',0,'Snort','TCP',445,NULL,'Commune'),

(1100006,2060006,'Heartbleed OpenSSL','Heartbleed OpenSSL','Intrusion',
'Heartbleed dans OpenSSL — fuite de mémoire exposant clés privées.',
'Heartbleed in OpenSSL — memory leak exposing private keys.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 443 -j DROP',0,'Snort','TCP',443,'CVE-2014-0160','Commune'),

(1100007,2060007,'Spring4Shell RCE','Spring4Shell Framework RCE','Intrusion',
'Exploitation Spring4Shell dans Spring Framework.',
'Spring4Shell exploitation in Spring Framework.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',80,'CVE-2022-22965','Commune'),

(1100008,2060008,'Citrix NetScaler RCE','Citrix NetScaler RCE','Intrusion',
'Exploitation RCE dans Citrix NetScaler.',
'Citrix NetScaler RCE exploitation.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2023-3519','Commune'),

(1100009,2060009,'Fortinet VPN Exploit','Fortinet FortiOS VPN Exploit','Intrusion',
'Exploitation vulnérabilités critiques FortiOS VPN.',
'Critical FortiOS VPN vulnerability exploitation.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2022-40684','Commune'),

(1100010,2060010,'MOVEit SQLi RCE','MOVEit Transfer SQL Injection RCE','Intrusion',
'Injection SQL critique MOVEit — exploitée massivement par cl0p.',
'Critical MOVEit SQL injection — massively exploited by cl0p.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2023-34362','Commune'),

(1100011,2060011,'Apache ActiveMQ RCE','Apache ActiveMQ RCE','Intrusion',
'RCE critique dans Apache ActiveMQ.',
'Critical Apache ActiveMQ RCE.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 61616 -j DROP',0,'Snort','TCP',61616,'CVE-2023-46604','Commune'),

(1100012,2060012,'Ivanti VPN Zero Day','Ivanti Connect Secure Zero Day','Intrusion',
'Zero-day Ivanti Connect Secure — très exploité en 2024.',
'Ivanti Connect Secure zero-day — heavily exploited in 2024.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2024-21887','Commune'),

(1100013,2060013,'OpenSSH PreAuth RCE','OpenSSH Pre-Auth RCE','Intrusion',
'RCE avant authentification OpenSSH — accès root sans identifiant.',
'Pre-auth OpenSSH RCE — root access without credentials.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 22 -j DROP',0,'Snort','TCP',22,'CVE-2024-6387','Commune'),

(1100014,2060014,'phpMyAdmin RCE','phpMyAdmin Remote Code Execution','Intrusion',
'RCE dans phpMyAdmin — très répandu sur serveurs africains.',
'phpMyAdmin RCE — very widespread on African servers.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2019-12922','Très commune'),

(1100015,2060015,'WordPress Plugin RCE','WordPress Plugin RCE','Intrusion',
'Exploitation plugin WordPress vulnérable — très fréquent.',
'Vulnerable WordPress plugin exploitation — very frequent.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,NULL,'Très commune'),

(1100016,2060016,'Palo Alto PAN-OS Exploit','Palo Alto PAN-OS Exploit','Intrusion',
'Exploitation vulnérabilité Palo Alto PAN-OS firewall.',
'Palo Alto PAN-OS firewall vulnerability exploitation.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2024-3400','Commune'),

(1100017,2060017,'GeoServer RCE','GeoServer Remote Code Execution','Intrusion',
'RCE dans GeoServer via injection OGC.',
'GeoServer RCE via OGC injection.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 8080 -j DROP',0,'Snort','TCP',8080,'CVE-2024-36401','Commune'),

(1100018,2060018,'Apache Struts RCE','Apache Struts RCE','Intrusion',
'RCE dans Apache Struts — responsable de la fuite Equifax.',
'Apache Struts RCE — responsible for Equifax breach.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',0,'Snort','TCP',80,'CVE-2017-5638','Commune'),

(1100019,2060019,'Zoho ManageEngine RCE','Zoho ManageEngine RCE','Intrusion',
'Exploitation RCE dans les produits Zoho ManageEngine.',
'Zoho ManageEngine RCE exploitation.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',8080,'CVE-2022-47966','Commune'),

(1100020,2060020,'VMware vCenter RCE','VMware vCenter Server RCE','Intrusion',
'RCE dans VMware vCenter — compromission totale infrastructure VM.',
'VMware vCenter RCE — full VM infrastructure compromise.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',0,'Snort','TCP',443,'CVE-2021-21985','Commune'),

-- ================================================================
-- 9. PRIVILEGE ESCALATION — 15 entrées
-- ================================================================

(90001,2070001,'Sudo Exploitation','Sudo Privilege Escalation','Privilege Escalation',
'Élévation de privilèges via mauvaise configuration sudo.',
'Privilege escalation via sudo misconfiguration.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90002,2070002,'SUID Binary Exploit','SUID Binary Exploit','Privilege Escalation',
'Exploitation d un binaire SUID pour obtenir des privilèges root.',
'SUID binary exploitation to obtain root privileges.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90003,2070003,'Kernel Exploit Linux','Linux Kernel Privilege Escalation','Privilege Escalation',
'Exploitation d une vulnérabilité kernel Linux pour obtenir root.',
'Linux kernel vulnerability exploitation to obtain root.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,'CVE-2023-0386','Commune'),

(90004,2070004,'Windows UAC Bypass','Windows UAC Bypass','Privilege Escalation',
'Contournement UAC Windows pour obtenir droits administrateur.',
'Windows UAC bypass to obtain administrator rights.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90005,2070005,'Pass-the-Hash','Pass-the-Hash Attack','Privilege Escalation',
'Utilisation d un hash NTLM pour s authentifier sans le mot de passe.',
'NTLM hash to authenticate without knowing the password.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90006,2070006,'Dirty COW Exploit','Dirty COW Linux Exploit','Privilege Escalation',
'Exploitation Dirty COW pour élévation de privilèges Linux.',
'Dirty COW exploitation for Linux privilege escalation.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,'CVE-2016-5195','Commune'),

(90007,2070007,'Crontab Modification Suspecte','Suspicious Crontab Modification','Privilege Escalation',
'Modification crontab pour maintenir une persistance avec droits élevés.',
'Crontab modification for persistent elevated access.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90008,2070008,'SSH Authorized Keys Modifiées','SSH Authorized Keys Modification','Privilege Escalation',
'Ajout clé SSH non autorisée dans authorized_keys — persistance attaquant.',
'Unauthorized SSH key added to authorized_keys — attacker persistence.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90009,2070009,'Nouveau Compte Root','New Root Account Created','Privilege Escalation',
'Création d un compte avec UID 0 (root) — backdoor potentielle.',
'Account with UID 0 created — potential backdoor.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90010,2070010,'Modification /etc/passwd','etc passwd Modification','Privilege Escalation',
'Modification du fichier /etc/passwd — risque de compte non autorisé.',
'/etc/passwd modification — unauthorized account risk.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90011,2070011,'Modification /etc/sudoers','etc sudoers Modification','Privilege Escalation',
'Modification du fichier sudoers — escalade de privilèges possible.',
'sudoers file modification — privilege escalation possible.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90012,2070012,'SUID Script Créé','SUID Script Created','Privilege Escalation',
'Création d un script SUID — peut mener à exécution root.',
'SUID script creation — can lead to root execution.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90013,2070013,'Token Impersonation','Token Impersonation Windows','Privilege Escalation',
'Impersonation de token Windows — accès à des ressources privilégiées.',
'Windows token impersonation — privileged resource access.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90014,2070014,'Service Modification Privilégiée','Privileged Service Modification','Privilege Escalation',
'Modification d un service Windows avec des droits non autorisés.',
'Windows service modification with unauthorized rights.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90015,2070015,'Scheduled Task Privilege Abuse','Scheduled Task Privilege Abuse','Privilege Escalation',
'Abus d une tâche planifiée pour exécution avec droits élevés.',
'Scheduled task abuse for elevated rights execution.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- 10. LATERAL MOVEMENT — 15 entrées
-- ================================================================

(95001,2080001,'Mouvement Latéral SMB','SMB Lateral Movement','Lateral Movement',
'Propagation latérale via SMB — typique des ransomwares.',
'SMB lateral propagation — typical ransomware behavior.',
4,'Isoler machine','iptables -A FORWARD -p tcp --dport 445 -j DROP',0,'Wazuh','TCP',445,NULL,'Commune'),

(95002,2080002,'PsExec Remote Execution','PsExec Remote Code Execution','Lateral Movement',
'Exécution distante via PsExec — outil souvent détourné pour propagation.',
'Remote execution via PsExec — tool often hijacked for propagation.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95003,2080003,'WMI Remote Execution','WMI Remote Execution','Lateral Movement',
'Exécution de code via WMI sur une machine distante.',
'Code execution via WMI on remote machine.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95004,2080004,'Kerberoasting Attack','Kerberoasting Attack','Lateral Movement',
'Extraction de tickets Kerberos pour craquer mots de passe hors ligne.',
'Kerberos ticket extraction for offline password cracking.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95005,2080005,'Mimikatz Credential Dumping','Mimikatz Credential Dumping','Lateral Movement',
'Mimikatz — extraction de mots de passe depuis la mémoire Windows.',
'Mimikatz — password extraction from Windows memory.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95006,2080006,'BloodHound AD Enumeration','BloodHound Active Directory Enumeration','Lateral Movement',
'BloodHound — cartographie Active Directory pour chemins d escalade.',
'BloodHound — Active Directory mapping for escalation paths.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95007,2080007,'Pass-the-Ticket Kerberos','Pass-the-Ticket Kerberos','Lateral Movement',
'Utilisation de tickets Kerberos volés pour accéder à des ressources.',
'Use of stolen Kerberos tickets to access resources.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95008,2080008,'DCOM Lateral Movement','DCOM Lateral Movement','Lateral Movement',
'Mouvement latéral via DCOM Windows.',
'Lateral movement via Windows DCOM.',
3,'Alerter',NULL,0,'Wazuh','TCP',135,NULL,'Commune'),

(95009,2080009,'RDP Lateral Movement','RDP Lateral Movement','Lateral Movement',
'Mouvement latéral via RDP depuis une machine déjà compromise.',
'Lateral movement via RDP from compromised machine.',
4,'Alerter',NULL,0,'Wazuh','TCP',3389,NULL,'Commune'),

(95010,2080010,'WPAD Proxy Hijack','WPAD Proxy Hijack','Lateral Movement',
'Détournement WPAD pour intercepter le trafic des machines du réseau.',
'WPAD hijack to intercept network machines traffic.',
3,'Alerter',NULL,0,'Wazuh','UDP',137,NULL,'Commune'),

-- ================================================================
-- 11. C2 — 15 entrées
-- ================================================================

(55001,2090001,'C2 Port Inhabituel','C2 Unusual Port Communication','C2',
'Communication sortante sur port inhabituel — possible canal C2.',
'Outbound on unusual port — possible C2 channel.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(55002,2090002,'DNS Tunneling C2','DNS Tunneling C2','C2',
'Tunnelisation de données via DNS — technique C2 difficile à détecter.',
'Data tunneling via DNS — C2 technique difficult to detect.',
4,'Bloquer IP','iptables -A OUTPUT -p udp --dport 53 -d {IP} -j DROP',0,'Snort','UDP',53,NULL,'Commune'),

(55003,2090003,'Cobalt Strike Beacon','Cobalt Strike HTTPS Beacon','C2',
'Beacon Cobalt Strike — framework d attaque utilisé par APT ciblant l Afrique.',
'Cobalt Strike beacon — attack framework used by APT targeting Africa.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',443,NULL,'Commune'),

(55004,2090004,'Metasploit Meterpreter','Metasploit Meterpreter Session','C2',
'Session Meterpreter — contrôle total de la machine compromise.',
'Meterpreter session — full compromised machine control.',
4,'Isoler machine','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(55005,2090005,'Tor Traffic Détecté','Tor Network Traffic','C2',
'Trafic Tor — possible exfiltration anonymisée ou canal C2.',
'Tor traffic — possible anonymized exfiltration or C2.',
3,'Alerter',NULL,0,'Snort','TCP',9001,NULL,'Commune'),

(55006,2090006,'Empire PowerShell C2','Empire PowerShell C2','C2',
'Framework Empire — C2 via PowerShell utilisé dans les attaques sans fichier.',
'Empire framework — C2 via PowerShell in fileless attacks.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(55007,2090007,'Sliver C2 Framework','Sliver Command and Control','C2',
'Sliver — alternative open source à Cobalt Strike de plus en plus utilisée.',
'Sliver — open source Cobalt Strike alternative increasingly used.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(55008,2090008,'ICMP Tunneling C2','ICMP Tunnel C2','C2',
'Tunnel C2 dans paquets ICMP — contourne les firewalls TCP/UDP.',
'C2 tunnel in ICMP packets — bypasses TCP/UDP firewalls.',
4,'Bloquer IP','iptables -A OUTPUT -p icmp -j DROP',0,'Snort','ICMP',NULL,NULL,'Commune'),

(55009,2090009,'DGA Domain Generation','DGA Domain Generation Algorithm','C2',
'DGA détecté — botnets génèrent des domaines aléatoires pour éviter le blocage.',
'DGA detected — botnets generate random domains to avoid blocking.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(55010,2090010,'C2 via Telegram API','Telegram C2 Channel','C2',
'API Telegram utilisée comme canal C2 — difficile à bloquer.',
'Telegram API used as C2 channel — difficult to block.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(55011,2090011,'HTTP Long Polling C2','HTTP Long Polling C2','C2',
'C2 via requêtes HTTP longues — imite le trafic web normal.',
'C2 via HTTP long polling — mimics normal web traffic.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(55012,2090012,'C2 via GitHub Gist','C2 via GitHub Gist','C2',
'GitHub Gist comme canal C2 furtif — trafic indiscernable du légitime.',
'GitHub Gist as stealthy C2 — traffic indistinguishable from legitimate.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(55013,2090013,'Fast Flux DNS','Fast Flux DNS Network','C2',
'Réseau Fast Flux — changement rapide d IPs pour masquer le C2.',
'Fast Flux network — rapid IP changes to hide C2.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','UDP',53,NULL,'Commune'),

(55014,2090014,'Havoc C2 Framework','Havoc Post-Exploitation Framework','C2',
'Havoc — framework C2 moderne avec contournement EDR intégré.',
'Havoc modern C2 framework with built-in EDR bypass.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

(55015,2090015,'Brute Ratel C4','Brute Ratel C4 Red Team Framework','C2',
'Brute Ratel C4 — framework C2 détecté dans des campagnes APT africaines.',
'Brute Ratel C4 — C2 framework detected in African APT campaigns.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',0,'Snort','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- 12. EXFILTRATION — 15 entrées
-- ================================================================

(98001,2095001,'Volume Sortant Anormal','Abnormal Outbound Data Volume','Exfiltration',
'Volume de données sortantes anormalement élevé — possible exfiltration.',
'Abnormally high outbound data volume — possible exfiltration.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(98002,2095002,'Exfiltration FTP','FTP Data Exfiltration','Exfiltration',
'Transfert FTP massif vers une IP externe — possible vol de données.',
'Mass FTP transfer to external IP — possible data theft.',
4,'Bloquer IP','iptables -A OUTPUT -s {IP_LOCALE} -p tcp --dport 21 -j DROP',0,'Snort','TCP',21,NULL,'Commune'),

(98003,2095003,'Exfiltration Cloud Storage','Cloud Storage Exfiltration','Exfiltration',
'Upload massif vers services cloud (Dropbox, Google Drive, Mega).',
'Mass upload to cloud services — possible exfiltration.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(98004,2095004,'Database Dump Détecté','Database Dump Detected','Exfiltration',
'Export complet d une base de données — possible vol de données massif.',
'Full database export — possible mass data theft.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(98005,2095005,'Email Exfiltration','Email Data Exfiltration','Exfiltration',
'Envoi massif d emails avec pièces jointes vers adresses externes.',
'Mass email with attachments to external addresses.',
4,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Commune'),

(98006,2095006,'HTTPS Exfiltration Chiffrée','HTTPS Encrypted Exfiltration','Exfiltration',
'Exfiltration chiffrée via HTTPS — volume anormalement élevé.',
'Encrypted exfiltration via HTTPS — abnormally high volume.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(98007,2095007,'DNS Exfiltration','DNS Data Exfiltration','Exfiltration',
'Exfiltration de données via des requêtes DNS encodées.',
'Data exfiltration via encoded DNS queries.',
3,'Alerter',NULL,0,'Snort','UDP',53,NULL,'Commune'),

(98008,2095008,'ICMP Exfiltration','ICMP Data Exfiltration','Exfiltration',
'Exfiltration de données dissimulée dans des paquets ICMP.',
'Data exfiltration hidden in ICMP packets.',
3,'Alerter',NULL,0,'Snort','ICMP',NULL,NULL,'Commune'),

(98009,2095009,'Credentials Exfiltration','Credentials Exfiltration','Exfiltration',
'Envoi de credentials volés vers un serveur externe.',
'Stolen credentials sent to external server.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',0,'Wazuh','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- 13. MOBILE — 20 entrées
-- Spécifique Afrique — Mobile Money, Fintech
-- ================================================================

(99001,2098001,'Android Banking Attack','Android Mobile Banking Attack','Mobile',
'Attaque sur application mobile bancaire Android — très ciblé en Afrique.',
'Android mobile banking app attack — heavily targeted in Africa.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(99002,2098002,'Interception SSL Mobile','Mobile SSL Interception','Mobile',
'Interception SSL d une app mobile — MITM sur connexion bancaire.',
'Mobile SSL interception — MITM on banking connection.',
4,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(99003,2098003,'SIM Swapping','SIM Swapping Attempt','Mobile',
'Portabilité frauduleuse de numéro — contourne la 2FA SMS.',
'Fraudulent SIM swap — bypasses SMS 2FA.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(99004,2098004,'USSD Attack Mobile Money','USSD Mobile Money Attack','Mobile',
'Exploitation vulnérabilité USSD — transactions Mobile Money frauduleuses.',
'USSD vulnerability exploitation — fraudulent Mobile Money transactions.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(99005,2098005,'Orange Money Phishing','Orange Money Phishing','Mobile',
'Phishing Orange Money — très utilisé en Afrique de l Ouest et Centrale.',
'Orange Money phishing — widely used in West and Central Africa.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Très commune'),

(99006,2098006,'Wave Money Phishing','Wave Money Phishing','Mobile',
'Phishing Wave — service dominant de transfert en Afrique de l Ouest.',
'Wave phishing — dominant transfer service in West Africa.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Très commune'),

(99007,2098007,'MTN MoMo Phishing','MTN Mobile Money Phishing','Mobile',
'Phishing MTN Mobile Money — 16 pays africains couverts.',
'MTN Mobile Money phishing — 16 African countries.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Très commune'),

(99008,2098008,'M-Pesa Phishing','M-Pesa Phishing','Mobile',
'Phishing M-Pesa — plateforme dominante Kenya/Afrique de l Est.',
'M-Pesa phishing — dominant Kenya/East Africa platform.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Commune'),

(99009,2098009,'APK Android Malveillant','Malicious Android APK','Mobile',
'APK malveillant distribué via WhatsApp ou boutiques non officielles.',
'Malicious APK via WhatsApp or unofficial stores.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(99010,2098010,'SMS Phishing Smishing','SMS Phishing Smishing','Mobile',
'Phishing par SMS — très utilisé en Afrique où le SMS est le canal principal.',
'SMS phishing — widely used in Africa where SMS is main channel.',
3,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(99011,2098011,'WhatsApp Scam Business','WhatsApp Business Scam','Mobile',
'Arnaque via WhatsApp Business — très répandu en Afrique de l Ouest.',
'WhatsApp Business scam — very common in West Africa.',
3,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(99012,2098012,'WhatsApp Account Takeover','WhatsApp Account Hijacking','Mobile',
'Prise de contrôle compte WhatsApp via code intercepté ou ingénierie sociale.',
'WhatsApp takeover via intercepted code or social engineering.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(99013,2098013,'Mobile Money Agent Fraud','Mobile Money Agent Scam','Mobile',
'Arnaque via un agent mobile money frauduleux.',
'Fraud via fraudulent mobile money agent.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(99014,2098014,'SS7 Protocol Attack','SS7 Telecom Protocol Attack','Mobile',
'Exploitation vulnérabilités SS7 — interception SMS et appels.',
'SS7 vulnerability exploitation — SMS and call interception.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Commune'),

(99015,2098015,'Android Banking Overlay','Android Banking Overlay Attack','Mobile',
'Malware superposant une fausse interface bancaire sur l app légitime.',
'Malware overlaying fake banking interface on legitimate app.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(99016,2098016,'Moov Money Phishing','Moov Money Phishing','Mobile',
'Phishing Moov Money — service présent en Afrique de l Ouest.',
'Moov Money phishing — service in West Africa.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Commune'),

(99017,2098017,'Airtel Money Phishing','Airtel Money Phishing','Mobile',
'Phishing Airtel Money — présent dans 14 pays africains.',
'Airtel Money phishing — present in 14 African countries.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Commune'),

(99018,2098018,'Fintech API Fraud','African Fintech API Fraud','Mobile',
'Fraude ciblant fintechs africaines (Flutterwave, Paystack) via API.',
'Fraud targeting African fintechs via API manipulation.',
4,'Alerter',NULL,0,'Custom','TCP',443,NULL,'Très commune'),

(99019,2098019,'Mobile Ransomware Android','Android Mobile Ransomware','Mobile',
'Ransomware Android — demande rançon via Mobile Money.',
'Android ransomware demanding ransom via Mobile Money.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Commune'),

(99020,2098020,'SIM Box Fraude Telecom','SIM Box Telecom Fraud','Mobile',
'Fraude SIM Box — routes voix illégales contournant les opérateurs africains.',
'SIM Box fraud — illegal voice routes bypassing African operators.',
3,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune');
-- ================================================================
--  SIEM Africa — Complément signatures (315 → 400+)
--  A ajouter à la fin de attacks.sql
-- ================================================================

INSERT OR IGNORE INTO attaques
(rule_id,sid_snort,nom,nom_en,categorie,description,description_en,
 gravite,action_recommandee,contre_mesure,faux_positif,source,
 protocole,port_cible,cve,frequence_afrique)
VALUES

-- ================================================================
-- BRUTE FORCE — complément (6 entrées)
-- ================================================================
(20361,2001341,'Brute Force Compte Wazuh','Wazuh Admin Brute Force','Brute Force',
'Tentatives de connexion brute force sur l API Wazuh port 55000.',
'Brute force on Wazuh API port 55000.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 55000 -j DROP',
0,'Wazuh','TCP',55000,NULL,'Commune'),

(20362,2001342,'Brute Force Grafana','Grafana Dashboard Brute Force','Brute Force',
'Brute force sur Grafana — outil de monitoring très utilisé.',
'Brute force on Grafana monitoring tool.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 3000 -j DROP',
0,'Snort','TCP',3000,NULL,'Commune'),

(20363,2001343,'Brute Force Portainer','Portainer Docker Brute Force','Brute Force',
'Brute force sur Portainer — interface de gestion Docker.',
'Brute force on Portainer Docker management interface.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 9000 -j DROP',
0,'Snort','TCP',9000,NULL,'Commune'),

(20364,2001344,'Brute Force Nextcloud','Nextcloud Brute Force','Brute Force',
'Brute force sur Nextcloud — cloud privé très utilisé par les entreprises africaines.',
'Brute force on Nextcloud private cloud.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',
0,'Snort','TCP',80,NULL,'Commune'),

(20365,2001345,'Brute Force AWX Ansible','AWX Ansible Brute Force','Brute Force',
'Brute force sur AWX — plateforme d automatisation Ansible.',
'Brute force on AWX Ansible automation platform.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',
0,'Snort','TCP',80,NULL,'Rare'),

(20366,2001346,'Brute Force Proxmox','Proxmox VE Brute Force','Brute Force',
'Brute force sur Proxmox Virtual Environment — hyperviseur open source.',
'Brute force on Proxmox Virtual Environment.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 8006 -j DROP',
0,'Snort','TCP',8006,NULL,'Commune'),

-- ================================================================
-- RECONNAISSANCE — complément (5 entrées)
-- ================================================================
(40151,1000051,'Scan Port 5432 PostgreSQL','PostgreSQL Port Scan','Reconnaissance',
'Scan ciblé du port PostgreSQL.',
'Targeted PostgreSQL port scan.',
2,'Alerter',NULL,0,'Snort','TCP',5432,NULL,'Commune'),

(40152,1000052,'Scan Port 6379 Redis Ciblé','Targeted Redis Port Scan','Reconnaissance',
'Scan ciblé du port Redis — base de données en mémoire souvent non protégée.',
'Targeted Redis port scan.',
3,'Alerter',NULL,0,'Snort','TCP',6379,NULL,'Très commune'),

(40153,1000053,'Scan Port 8443 HTTPS Alt','Alternative HTTPS Port Scan','Reconnaissance',
'Scan du port HTTPS alternatif 8443.',
'Alternative HTTPS port 8443 scan.',
1,'Observer',NULL,1,'Snort','TCP',8443,NULL,'Commune'),

(40154,1000054,'Scan Port 2222 SSH Alt','Alternative SSH Port Scan','Reconnaissance',
'Scan du port SSH alternatif 2222 — les admins le changent pour éviter les scans.',
'Alternative SSH port 2222 scan.',
2,'Alerter',NULL,0,'Snort','TCP',2222,NULL,'Commune'),

(40155,1000055,'Scan Infrastructure Critique','Critical Infrastructure Recon','Reconnaissance',
'Reconnaissance ciblée sur infrastructure critique africaine — energie, eau, telecoms.',
'Targeted recon on African critical infrastructure.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- WEB ATTACK — complément (10 entrées)
-- ================================================================
(31510,2006850,'Server Side Prototype Pollution','Server Side Prototype Pollution','Web Attack',
'Pollution du prototype JavaScript côté serveur — peut mener à RCE sur Node.js.',
'Server-side JavaScript prototype pollution — can lead to RCE on Node.js.',
4,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31520,2006860,'XML Injection','XML Injection Attack','Web Attack',
'Injection XML dans des paramètres non filtrés — manipulation de données XML.',
'XML injection in unfiltered parameters.',
3,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',
0,'Snort','TCP',80,NULL,'Commune'),

(31530,2006870,'HTTP Parameter Pollution','HTTP Parameter Pollution','Web Attack',
'Pollution des paramètres HTTP — contourne les validations côté serveur.',
'HTTP parameter pollution to bypass server-side validations.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31540,2006880,'Insecure Direct Object Reference','IDOR Sensitive Data','Web Attack',
'Accès direct à des objets sensibles sans contrôle d autorisation.',
'Direct access to sensitive objects without authorization check.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31550,2006890,'Business Logic Bypass','Business Logic Vulnerability','Web Attack',
'Contournement de la logique métier — manipulation des processus applicatifs.',
'Business logic bypass — manipulation of application processes.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

(31560,2006900,'Race Condition Exploit','Race Condition Attack','Web Attack',
'Exploitation d une condition de course dans une application web.',
'Race condition exploitation in web application.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Rare'),

(31570,2006910,'Path Confusion Attack','Path Confusion Attack','Web Attack',
'Confusion de chemin exploitant des différences d interprétation entre composants.',
'Path confusion exploiting interpretation differences between components.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Rare'),

(31580,2006920,'ReDoS Regular Expression DoS','ReDoS Regular Expression DoS','Web Attack',
'Déni de service via des expressions régulières catastrophiques.',
'Denial of service via catastrophic regular expressions.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Rare'),

(31590,2006930,'CSS Injection','CSS Injection Attack','Web Attack',
'Injection CSS pour voler des données ou modifier l apparence d une page.',
'CSS injection to steal data or modify page appearance.',
2,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Rare'),

(31600,2006940,'iFrame Injection','Malicious iFrame Injection','Web Attack',
'Injection d iFrame malveillant dans une page web légitime.',
'Malicious iFrame injection in legitimate web page.',
3,'Alerter',NULL,0,'Snort','TCP',80,NULL,'Commune'),

-- ================================================================
-- INTRUSION — complément (5 entrées)
-- ================================================================
(1100021,2060021,'PaperCut RCE','PaperCut Print Server RCE','Intrusion',
'Exploitation RCE dans PaperCut — serveur d impression d entreprise.',
'PaperCut print server RCE exploitation.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 9191 -j DROP',
0,'Snort','TCP',9191,'CVE-2023-27350','Commune'),

(1100022,2060022,'GoAnywhere MFT RCE','GoAnywhere MFT Zero Day','Intrusion',
'Zero-day dans GoAnywhere MFT — exploité par des groupes ransomware.',
'GoAnywhere MFT zero-day exploited by ransomware groups.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -j DROP',
0,'Snort','TCP',8022,'CVE-2023-0669','Commune'),

(1100023,2060023,'Roundcube XSS to RCE','Roundcube XSS RCE Chain','Intrusion',
'XSS persistant dans Roundcube menant à RCE — utilisé par APT28.',
'Persistent XSS in Roundcube leading to RCE — used by APT28.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',
0,'Snort','TCP',80,'CVE-2023-43770','Commune'),

(1100024,2060024,'Cacti Network Monitor RCE','Cacti RCE','Intrusion',
'RCE dans Cacti via injection dans la configuration du poller.',
'Cacti RCE via poller configuration injection.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 80 -j DROP',
0,'Snort','TCP',80,'CVE-2022-46169','Commune'),

(1100025,2060025,'Weblogic RCE Oracle','Oracle WebLogic RCE','Intrusion',
'Exploitation RCE dans Oracle WebLogic Server.',
'Oracle WebLogic Server RCE exploitation.',
4,'Bloquer IP','iptables -A INPUT -s {IP} -p tcp --dport 7001 -j DROP',
0,'Snort','TCP',7001,'CVE-2023-21839','Commune'),

-- ================================================================
-- RANSOMWARE — complément (5 entrées)
-- ================================================================
(60016,2030016,'Qilin Ransomware','Qilin Ransomware','Ransomware',
'Qilin — ransomware émergent ciblant Linux et VMware ESXi.',
'Qilin emerging ransomware targeting Linux and VMware ESXi.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Custom','TCP',NULL,NULL,'Commune'),

(60017,2030017,'Play Ransomware','Play Ransomware','Ransomware',
'Play — groupe ransomware actif ciblant les entreprises africaines.',
'Play ransomware group targeting African companies.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Custom','TCP',NULL,NULL,'Commune'),

(60018,2030018,'Akira Ransomware','Akira Ransomware','Ransomware',
'Akira — ransomware récent ciblant les PME. Double extorsion.',
'Akira ransomware targeting SMEs. Double extortion.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Custom','TCP',NULL,NULL,'Commune'),

(60019,2030019,'Ransomware Propagation SMB','Ransomware SMB Propagation','Ransomware',
'Propagation du ransomware sur le réseau local via SMB.',
'Ransomware propagation on local network via SMB.',
4,'Isoler machine','iptables -A FORWARD -p tcp --dport 445 -j DROP',
0,'Wazuh','TCP',445,NULL,'Commune'),

(60020,2030020,'Wiper Malware Destruction','Wiper Malware Data Destruction','Ransomware',
'Malware de type wiper — destruction irréversible des données.',
'Wiper malware — irreversible data destruction.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Custom','TCP',NULL,NULL,'Rare'),

-- ================================================================
-- MALWARE — complément (5 entrées)
-- ================================================================
(70045,2040045,'Formbook Stealer','Formbook Form Grabber','Malware',
'Formbook — grabber de formulaires web très répandu en Afrique.',
'Formbook web form grabber very common in Africa.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Snort','TCP',NULL,NULL,'Très commune'),

(70046,2040046,'IcedID Banking Trojan','IcedID Bokbot Banking Trojan','Malware',
'IcedID — trojan bancaire ciblant les transactions financières des PME.',
'IcedID banking trojan targeting SME financial transactions.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Snort','TCP',NULL,NULL,'Commune'),

(70047,2040047,'Trickbot Malware','Trickbot Banking Trojan','Malware',
'TrickBot — malware modulaire pour vol credentials et déploiement ransomware.',
'TrickBot modular malware for credential theft and ransomware deployment.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Snort','TCP',NULL,NULL,'Commune'),

(70048,2040048,'Dridex Banking Malware','Dridex Banking Malware','Malware',
'Dridex — malware bancaire ciblant les services financiers.',
'Dridex banking malware targeting financial services.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Snort','TCP',NULL,NULL,'Commune'),

(70049,2040049,'XWorm RAT','XWorm Remote Access Trojan','Malware',
'XWorm — RAT avec keylogger, ransomware et vol de crypto intégrés.',
'XWorm RAT with keylogger, ransomware and crypto theft.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Snort','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- PHISHING / BEC — complément (5 entrées)
-- ================================================================
(80021,2050021,'Phishing Recrutement Emploi','Job Recruitment Phishing','Phishing',
'Phishing via de fausses offres d emploi — très répandu en Afrique avec le chômage élevé.',
'Phishing via fake job offers — very common in Africa given high unemployment.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Très commune'),

(80022,2050022,'BEC Fausse Demande IT','BEC Fake IT Request','BEC',
'Usurpation du service IT pour obtenir des identifiants ou réinitialiser des MDP.',
'IT department impersonation to obtain credentials or reset passwords.',
3,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Commune'),

(80023,2050023,'Phishing COVID Actualite','Current Events Phishing','Phishing',
'Phishing exploitant l actualité — COVID, élections, catastrophes naturelles.',
'Phishing exploiting current events — COVID, elections, natural disasters.',
3,'Alerter',NULL,0,'Wazuh','TCP',25,NULL,'Commune'),

(80024,2050024,'Escroquerie Investissement Crypto','Crypto Investment Scam','Phishing',
'Escroquerie aux investissements crypto — schéma de Ponzi ou fausse plateforme.',
'Crypto investment scam — Ponzi scheme or fake exchange platform.',
3,'Alerter',NULL,0,'Custom','TCP',443,NULL,'Très commune'),

(80025,2050025,'Phishing Fintech Africaine','African Fintech Phishing','Phishing',
'Phishing ciblant les fintechs africaines — Flutterwave, Paystack, Chipper.',
'Phishing targeting African fintechs — Flutterwave, Paystack, Chipper.',
4,'Alerter',NULL,0,'Custom','TCP',443,NULL,'Très commune'),

-- ================================================================
-- PRIVILEGE ESCALATION — complément (5 entrées)
-- ================================================================
(90016,2070016,'Modification Services Windows','Windows Service Modification','Privilege Escalation',
'Modification d un service Windows pour exécution avec droits élevés.',
'Windows service modification for elevated rights execution.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90017,2070017,'DLL Hijacking','DLL Hijacking Attack','Privilege Escalation',
'Détournement de DLL Windows pour exécuter du code malveillant avec droits élevés.',
'Windows DLL hijacking to execute malicious code with elevated rights.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90018,2070018,'Token Impersonation Windows','Windows Token Impersonation','Privilege Escalation',
'Impersonation de token Windows — accès à des ressources privilégiées.',
'Windows token impersonation — privileged resource access.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90019,2070019,'Named Pipe Privilege Escalation','Named Pipe Privilege Escalation','Privilege Escalation',
'Élévation de privilèges via les named pipes Windows.',
'Windows named pipe privilege escalation.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(90020,2070020,'AppLocker Bypass','AppLocker Security Bypass','Privilege Escalation',
'Contournement d AppLocker pour exécuter du code non autorisé.',
'AppLocker bypass to execute unauthorized code.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- LATERAL MOVEMENT — complément (5 entrées)
-- ================================================================
(95011,2080011,'NTLM Relay Attack','NTLM Relay Attack','Lateral Movement',
'Attaque NTLM Relay pour s authentifier sur d autres machines du réseau.',
'NTLM relay attack to authenticate on other network machines.',
4,'Alerter',NULL,0,'Wazuh','TCP',445,NULL,'Commune'),

(95012,2080012,'SMB Signing Disabled','SMB Signing Disabled Exploit','Lateral Movement',
'Exploitation de la signature SMB désactivée pour des attaques MITM.',
'SMB signing disabled exploitation for MITM attacks.',
3,'Alerter',NULL,0,'Wazuh','TCP',445,NULL,'Commune'),

(95013,2080013,'DCSync Attack','DCSync Active Directory Attack','Lateral Movement',
'DCSync — simule un contrôleur de domaine pour extraire les hashs NTLM.',
'DCSync — simulates domain controller to extract NTLM hashes.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95014,2080014,'Golden Ticket Kerberos','Golden Ticket Kerberos Attack','Lateral Movement',
'Golden Ticket — forge un ticket Kerberos pour un accès illimité au domaine.',
'Golden Ticket — forges Kerberos ticket for unlimited domain access.',
4,'Isoler machine',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(95015,2080015,'Silver Ticket Kerberos','Silver Ticket Kerberos Attack','Lateral Movement',
'Silver Ticket — accès à un service spécifique sans passer par le KDC.',
'Silver Ticket — service access without going through KDC.',
4,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- C2 — complément (5 entrées)
-- ================================================================
(55016,2090016,'C2 via Discord','Discord C2 Channel','C2',
'Discord utilisé comme canal de commande et contrôle.',
'Discord used as command and control channel.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(55017,2090017,'C2 via Google Forms','Google Forms C2','C2',
'Google Forms utilisé comme canal C2 discret.',
'Google Forms used as discreet C2 channel.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(55018,2090018,'C2 via Pastebin','Pastebin C2 Channel','C2',
'Pastebin pour stocker des commandes C2 — technique Living off the Land.',
'Pastebin to store C2 commands — Living off the Land technique.',
3,'Alerter',NULL,0,'Snort','TCP',443,NULL,'Commune'),

(55019,2090019,'Nighthawk C2 Framework','Nighthawk C2 Framework','C2',
'Nighthawk — framework C2 commercial avec techniques d évasion avancées.',
'Nighthawk commercial C2 framework with advanced evasion techniques.',
4,'Bloquer IP','iptables -A OUTPUT -d {IP} -j DROP',
0,'Snort','TCP',NULL,NULL,'Commune'),

(55020,2090020,'IRC Bot C2','IRC Bot C2 Communication','C2',
'Communication bot via IRC — canal C2 classique toujours utilisé.',
'Bot communication via IRC — classic C2 channel still used.',
3,'Bloquer IP','iptables -A OUTPUT -d {IP} -p tcp --dport 6667 -j DROP',
0,'Snort','TCP',6667,NULL,'Commune'),

-- ================================================================
-- EXFILTRATION — complément (5 entrées)
-- ================================================================
(98010,2095010,'Exfiltration via USB','USB Data Exfiltration','Exfiltration',
'Copie de données sensibles vers un support USB détecté.',
'Sensitive data copy to USB drive detected.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(98011,2095011,'Exfiltration via Impression','Print Data Exfiltration','Exfiltration',
'Impression massive de documents sensibles — exfiltration physique.',
'Mass printing of sensitive documents — physical exfiltration.',
2,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(98012,2095012,'Exfiltration Screenshots','Screenshot Data Exfiltration','Exfiltration',
'Captures d écran automatiques de données sensibles envoyées vers l extérieur.',
'Automatic screenshots of sensitive data sent externally.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Commune'),

(98013,2095013,'Exfiltration via Bluetooth','Bluetooth Data Exfiltration','Exfiltration',
'Transfert de données via Bluetooth vers un appareil non autorisé.',
'Data transfer via Bluetooth to unauthorized device.',
3,'Alerter',NULL,0,'Wazuh','TCP',NULL,NULL,'Rare'),

(98014,2095014,'Exfiltration Credentials Dump','Credentials Dump Exfiltration','Exfiltration',
'Envoi de credentials volés vers un serveur externe.',
'Stolen credentials sent to external server.',
4,'Isoler machine','iptables -A OUTPUT -s {IP_LOCALE} -j DROP',
0,'Wazuh','TCP',NULL,NULL,'Commune'),

-- ================================================================
-- MOBILE — complément (5 entrées)
-- ================================================================
(99021,2098021,'Fake App Mobile Banking','Fake Mobile Banking App','Mobile',
'Fausse application bancaire mobile imitant une vraie banque africaine.',
'Fake mobile banking app impersonating real African bank.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Très commune'),

(99022,2098022,'Mobile Phone Cloning IMSI','IMSI Mobile Phone Cloning','Mobile',
'Clonage de carte SIM — interception SMS et appels.',
'SIM cloning — SMS and call interception.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Commune'),

(99023,2098023,'Stalkerware Mobile','Mobile Stalkerware Detection','Mobile',
'Logiciel espion installé à l insu sur un smartphone.',
'Spy software secretly installed on smartphone.',
3,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Commune'),

(99024,2098024,'Mobile Ransomware Lock','Mobile Device Ransomware Lock','Mobile',
'Ransomware bloquant le téléphone — demande rançon via Mobile Money.',
'Ransomware locking phone — demands ransom via Mobile Money.',
4,'Alerter',NULL,0,'Custom','TCP',NULL,NULL,'Commune'),

(99025,2098025,'Free Senegal Money Phishing','Free Senegal Money Phishing','Mobile',
'Phishing ciblant Free Money Mobile au Sénégal.',
'Phishing targeting Free Mobile Money in Senegal.',
3,'Alerter',NULL,0,'Custom','TCP',80,NULL,'Commune');

-- ================================================================
-- MAPPING MITRE ATT&CK
-- Ajout des identifiants MITRE sur toutes les signatures
-- ================================================================

-- Brute Force
UPDATE attaques SET mitre_id='T1110',     mitre_tactique='Credential Access'   WHERE categorie='Brute Force';
UPDATE attaques SET mitre_id='T1110.001', mitre_tactique='Credential Access'   WHERE categorie='Brute Force' AND (nom LIKE '%Dictionnaire%' OR nom LIKE '%Password Spray%');
UPDATE attaques SET mitre_id='T1110.004', mitre_tactique='Credential Access'   WHERE categorie='Brute Force' AND nom LIKE '%SSH%';
UPDATE attaques SET mitre_id='T1110.003', mitre_tactique='Credential Access'   WHERE categorie='Brute Force' AND nom LIKE '%RDP%';

-- Web Attack
UPDATE attaques SET mitre_id='T1190',     mitre_tactique='Initial Access'      WHERE categorie='Web Attack';
UPDATE attaques SET mitre_id='T1059.007', mitre_tactique='Execution'           WHERE categorie='Web Attack' AND (nom LIKE '%XSS%' OR nom LIKE '%Script%');
UPDATE attaques SET mitre_id='T1505.003', mitre_tactique='Persistence'         WHERE categorie='Web Attack' AND nom LIKE '%Webshell%';
UPDATE attaques SET mitre_id='T1190',     mitre_tactique='Initial Access'      WHERE categorie='Web Attack' AND nom LIKE '%Log4%';

-- Reconnaissance
UPDATE attaques SET mitre_id='T1046',     mitre_tactique='Discovery'           WHERE categorie='Reconnaissance';
UPDATE attaques SET mitre_id='T1595.001', mitre_tactique='Reconnaissance'      WHERE categorie='Reconnaissance' AND nom LIKE '%Nmap%';
UPDATE attaques SET mitre_id='T1595.002', mitre_tactique='Reconnaissance'      WHERE categorie='Reconnaissance' AND nom LIKE '%Masscan%';
UPDATE attaques SET mitre_id='T1592',     mitre_tactique='Reconnaissance'      WHERE categorie='Reconnaissance' AND nom LIKE '%WPScan%';

-- Ransomware
UPDATE attaques SET mitre_id='T1486',     mitre_tactique='Impact'              WHERE categorie='Ransomware';
UPDATE attaques SET mitre_id='T1490',     mitre_tactique='Impact'              WHERE categorie='Ransomware' AND nom LIKE '%Shadow%';

-- Malware
UPDATE attaques SET mitre_id='T1059',     mitre_tactique='Execution'           WHERE categorie='Malware';
UPDATE attaques SET mitre_id='T1071',     mitre_tactique='Command and Control' WHERE categorie='Malware' AND (nom LIKE '%RAT%' OR nom LIKE '%Remote%');
UPDATE attaques SET mitre_id='T1055',     mitre_tactique='Defense Evasion'     WHERE categorie='Malware' AND nom LIKE '%Inject%';

-- C2
UPDATE attaques SET mitre_id='T1071',     mitre_tactique='Command and Control' WHERE categorie='C2';
UPDATE attaques SET mitre_id='T1071.004', mitre_tactique='Command and Control' WHERE categorie='C2' AND nom LIKE '%DNS%';
UPDATE attaques SET mitre_id='T1095',     mitre_tactique='Command and Control' WHERE categorie='C2' AND nom LIKE '%Cobalt%';

-- Phishing
UPDATE attaques SET mitre_id='T1566',     mitre_tactique='Initial Access'      WHERE categorie='Phishing';
UPDATE attaques SET mitre_id='T1566.002', mitre_tactique='Initial Access'      WHERE categorie='Phishing' AND nom LIKE '%lien%';
UPDATE attaques SET mitre_id='T1598',     mitre_tactique='Reconnaissance'      WHERE categorie='BEC';

-- Privilege Escalation
UPDATE attaques SET mitre_id='T1068',     mitre_tactique='Privilege Escalation' WHERE categorie='Privilege Escalation';
UPDATE attaques SET mitre_id='T1548.003', mitre_tactique='Privilege Escalation' WHERE categorie='Privilege Escalation' AND nom LIKE '%Sudo%';
UPDATE attaques SET mitre_id='T1547',     mitre_tactique='Persistence'          WHERE categorie='Privilege Escalation' AND nom LIKE '%SUID%';

-- Lateral Movement
UPDATE attaques SET mitre_id='T1021',     mitre_tactique='Lateral Movement'    WHERE categorie='Lateral Movement';
UPDATE attaques SET mitre_id='T1550',     mitre_tactique='Lateral Movement'    WHERE categorie='Lateral Movement' AND nom LIKE '%Hash%';
UPDATE attaques SET mitre_id='T1558',     mitre_tactique='Credential Access'   WHERE categorie='Lateral Movement' AND nom LIKE '%Kerberos%';

-- Exfiltration
UPDATE attaques SET mitre_id='T1041',     mitre_tactique='Exfiltration'        WHERE categorie='Exfiltration';
UPDATE attaques SET mitre_id='T1048.003', mitre_tactique='Exfiltration'        WHERE categorie='Exfiltration' AND nom LIKE '%DNS%';
UPDATE attaques SET mitre_id='T1567',     mitre_tactique='Exfiltration'        WHERE categorie='Exfiltration' AND nom LIKE '%Cloud%';

-- DDoS et DoS
UPDATE attaques SET mitre_id='T1498',     mitre_tactique='Impact'              WHERE categorie='DDoS';
UPDATE attaques SET mitre_id='T1499',     mitre_tactique='Impact'              WHERE categorie='DoS';

-- Mobile
UPDATE attaques SET mitre_id='T1566',     mitre_tactique='Initial Access'      WHERE categorie='Mobile';

-- Intrusion
UPDATE attaques SET mitre_id='T1190',     mitre_tactique='Initial Access'      WHERE categorie='Intrusion';
UPDATE attaques SET mitre_id='T1203',     mitre_tactique='Execution'           WHERE categorie='Intrusion' AND nom LIKE '%Exploit%';

-- Crypto
UPDATE attaques SET mitre_id='T1496',     mitre_tactique='Impact'              WHERE categorie='Crypto';
