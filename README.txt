The purpose of this script is to satisfy all of the basic DISA STIG requirements for the "Layer 2 - Cisco "and "Network Device Management (NDM) - IOS XE NDM" STIGs.

This script, if used fully, will bring NDM to roughly 90% and L2 to roughly 75%; this does not take into account any environmental or organization-dependent answers.

Once deployed, the following STIG Vulnerability IDs can be marked "Not a Finding," with accompanying justification. 
Below are my notes when going over this STIG checklist. You will find the accompanying command section in ###'s.
NOTE: I do not include the native / unused VLAN checks in the below list. Using that portion of my program will increase the STIG scores.

VID = Vulnerability ID
N = NDM
X = IOS XE NDM
L = L2
C = CISCO L2

###VTY LINES###
--Commands:
	line vty 0 {vty - 1 }
	session-timeout 10
	session-limit {users} 
	exec-timeout 10 0
	lockable 
	transport input ssh
	transport output ssh
	line console 0
	session-timeout 10
	exec-timeout 10 0
	lockable 
	line aux 0 
	no exec

These protections resolve the following VIDs: 
(N) 55027, 55031, 55033, 55035, 55159, 55195 
(X) 74027, 74031, 74053, 74055 
(CL) 3014, 3967, 7011

###LOGGING###
--Commands:
	logging host {IP}
	logging trap information
	logging userinfo
	archive
	log config
	logging enable
	logging size 1000
	notify syslog contenttype plaintext
	hidekeys
	login on-failure log every 1
	login on-success log every 1
	logging buffered {size}

These protections resolve the following VIDs:
(N) 55043, 55045, 55049, 55067, 55075, 55085, 55087, 55091, 55093, 55095, 55099, 55129, 55137, 55143, 55147, 55203, 55209, 55273, 55275, 55277, 55279, 55281, 55283, 55285, 55287, 55289
(X) 73965, 73969, 73967, 73979, 73985, 73987, 73989, 73993, 73995, 73997, 73999, 74001, 74005, 74033, 74035, 74039, 74061, 74063, 74065, 74067, 74069, 74071, 74073, 74075, 74085
(CL) 3070, 4584

###SERVICES###
--Commands:
	disable
	 	no ip bootp server
		no ip dns server
		no ip identd
		no ip finger
		no ip http-server
		no ip rcmd rcp-enable
		no ip rcmd rsh-enable
		no service config
		no service finger
		no service tcp-small-servers
		no service udp-small-servers
		no service pad
		no ip domain-lookup
		no service call-home
	enable
		service timestamps log datetime year
		service timestamps debug datetime msec
		service timestamps datetime localtime
		service tcp-keepalives in
		service password-encryption

These protections resolve the following VIDs: 		
(N) 55097, 55101, 55131, 55133, 55165, 55233, 55235
(X) 73991, 74003, 74007, 74023, 74047, 74049, 
(CL) 3020, 3062, 3078, 3079, 3085, 5614, 5615, 14669, 28784

###SSH###
--Commands:
	ip domain-name {domain-name}
	crypto key generate rsa modulus {selected mod}
	ip ssh time-out 60
	ip ssh authentication-retries 3
	ip ssh version 2
	login block-for 600 attempts 3 within 900

These protections resolve the following VIDs: 
(N) 55055, 55059, 55265, 55267
(X) 73973
(CL) 3069, 5612, 5613, 14717

###NTP###
--Commands:
	ntp authentication-key {key1} md5 {pass1}
	ntp authentication-key {key2} md5 {pass2}
	ntp trusted-key {key1}
	ntp trusted-key {key2}
	ntp authenticate
	ntp server {ip1} key {key1}
	ntp server {ip2} key {key2}

These protections resolve the following VIDs: 
(N) 55081, 55083, 55231, 
(X) 74041, 74043, 74045, 
(CL) 14671, 23747

###USER AGREEMENT AND LAST RESORT###
###ENABLE SECRET###
--Commands:
	(if question 1 = YES) banner login * 
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE, or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
*
	no username cisco
	no username admin
	(if question 3 = YES) username {username} privilege 15 password 0 {password}
	(if question 6 = YES) enable secret 0 {pass2}
	
These protections resolve the following VIDs: 
(N) 55057, 55059, 63997, 64001
(X) 73975, 73977, 74009
(CL) 3012, 3013, 3143, 3966, 15434

###AAA###
--Commands:
	aaa new-model
	aaa authentication login default group {rad/tac} local
	{rad/tac}-server host {ip1} key {key1}
	(if question 6 = YES) {rad/tac}-server host {ip2} key {key2}

These protections resolve the following VIDs: 
(N) 55037, 55211
(X) 73963
(CL) 3175, 4582, 15432



