#do not forget to python -m pip install netmiko
import netmiko
import getpass
import sys
import time


#List of devices to SSH to, based on the entries in the text file.
ip_list = open("FILE LOCATION") #Input file location
#Connection
username = input("Username: ")
password = getpass.getpass()
secret = input("Enable Secret: ")


###ORIGINAL QUESTION-BASED INPUTS###
#print("Please answer the following questions regarding your STIG deployment.\n")
###VTY LINES###
#vty_lines = int(input("How many VTY lines does your device have? (e.g. 0-15 = 16) "))
#ssh_users = input("How many concurrent SSH sessions does your organization allow? ")
###LOGGING###
#log_ip_1 = input("What is the logging server IP? ")
#log_buffer_1 = input("How large would you like to set the logging buffer? ")

#log_ip_2 = input("What is the logging server IP? ")
###SSH###
#domain_name = input("What is your full domain name? ").lower()
#set_modulus = input("Would you like to generate a 2048 or 4096 modulus? ")
###NTP###
#print("NOTE: Two geographically separate NTP servers must be used to adhere to STIG VID 23747.")
#ntp_ip_1 = input("What is the NTP server IP? ")
#ntp_key_1 = input("What is the key number? ")
#ntp_pass_1 = input("What is the plaintext password? ")
#ntp_ip_2 = input("What is the NTP server IP? ")
#ntp_key_2 = input("What is the key number? ")
#ntp_pass_2 = input("What is the plaintext password? ")
###LAST RESORT ACCT###
#last_user = input("What is the username of last resort? ")
#last_pass = input("What is the plaintext password of last resort? ")
###ENABLE SECRET###
#secret_pass = input("What is the plaintext password for enable secret? ")
###AAA###
#rad_tac_1 = input("RADIUS or TACACS+? ")
#aaa_ip_1 = input("What is the IP of the AAA server? ")
#aaa_key_1 = input("What is the plaintext pre-shared key? ")
#rad_tac_2 = input("RADIUS or TACACS+? ")
#aaa_ip_2 = input("What is the IP of the AAA server? ")
#aaa_key_2 = input("What is the plaintext pre-shared key? ")
###UNUSED / CATCH-ALL VLAN###
#unused_vlan = input("Which VLAN is the unused VLAN? (number only) ")
###NATIVE VLAN###
#native_vlan = input("What is the native VLAN? (number only) ")

###SET ANY INPUT = TO DESIRED INPUT FOR AUTO-CONFIG, OTHERWISE USE ABOVE###
###IF YOU DO NOT WANT TO CONFIGURE ANY "2" SERVICES (E.G. 2 NTP SERVERS), ENSURE THE 2ND VARIABLE = NONE###
###VTY LINES###
vty_lines = 16
    #How many VTY lines does your device have? (e.g. 0-15 = 16)
ssh_users = ""
    #How many concurrent SSH sessions does your organization allow?
###LOGGING###
log_ip_1 = ""
    #"What is the logging server IP?
log_buffer_1 = ""
    #How large would you like to set the logging buffer?

log_ip_2 = None
    #What is the logging server IP?
###SSH###
domain_name = ""
    #What is your full domain name?
set_modulus = ""
    #Would you like to generate a 2048 or 4096 modulus?
###NTP###
###NOTE: Two geographically separate NTP servers must be used to adhere to STIG VID 23747###
ntp_ip_1 = ""
    #What is the NTP server IP?
ntp_key_1 = ""
    #What is the key number?
ntp_pass_1 = ""
    #What is the plaintext password?

ntp_ip_2 = None
    #What is the NTP server IP?
ntp_key_2 = None
    #What is the key number?
ntp_pass_2 = None
    #What is the plaintext password?
###LAST RESORT ACCT###
last_user = ""
    #What is the username of last resort?
last_pass = ""
    #What is the plaintext password of last resort?
###ENABLE SECRET###
secret_pass = ""
    #What is the plaintext password for enable secret?
###AAA###
rad_tac_1 = ""
    #RADIUS or TACACS+?
aaa_ip_1 = ""
    #What is the IP of the AAA server?
aaa_key_1 = ""
    #What is the plaintext pre-shared key?

rad_tac_2 = None
    #RADIUS or TACACS+?
aaa_ip_2 = None
    #What is the IP of the AAA server?
aaa_key_2 = None
    #What is the plaintext pre-shared key?
###UNUSED / CATCH-ALL VLAN###
unused_vlan = ""
    #Which VLAN is the unused VLAN? (number only)
###NATIVE VLAN###
native_vlan = ""
    #What is the native VLAN? (number only)




###VTY LINES###
vty_cfg_cmd = ([f"line vty 0 {vty_lines - 1}", "session-timeout 10", f"session-limit {ssh_users}", "exec-timeout 10 0",
 "lockable", "transport input ssh", "transport output ssh", "line console 0", "session-timeout 10",
 "exec-timeout 10 0", "lockable", "line aux 0", "no exec"])

###LOGGING###
log_1_cfg_cmd = ([f"logging host {log_ip_1}", "logging trap information", "logging userinfo", "archive",
"log config", "logging enable", "logging size 1000", "notify syslog contenttype plaintext",
"hidekeys", "login on-failure log every 1", "login on-success log every 1",
f"logging buffered {log_buffer_1}"])
log_2_cfg_cmd = ([f"logging host {log_ip_2}"])

###SERVICES###
svc_dis_cfg_cmd = (["no ip bootp server", "no ip dns server", "no ip identd", "no ip finger", "no ip http server",
"no ip rcmd rcp-enable", "no ip rcmd rsh-enable", "no service config", "no service finger",
"no service tcp-small-servers", "no service udp-small-servers", "no service pad",
"no ip domain-lookup", "no service call-home", ])
svc_en_cfg_cmd = (["service timestamps debug datetime msec", "service timestamps log datetime localtime year",
"service tcp-keepalives in", "service password-encryption", ])

###SSH###
ssh_cfg_cmd = ([f"ip domain-name {domain_name}", f"crypto key generate rsa modulus {set_modulus}", "ip ssh time-out 60",
"ip ssh authentication-retries 3", "ip ssh version 2", "login block-for 600 attempts 3 within 900", ])

###NTP###
ntp_cfg_cmd_1 = ([f"ntp authentication-key {ntp_key_1} md5 {ntp_pass_1}", f"ntp trusted-key {ntp_key_1}",
"ntp authenticate", f"ntp server {ntp_ip_1} key {ntp_key_1}"])
ntp_cfg_cmd_2 = ([f"ntp authentication-key {ntp_key_2} md5 {ntp_pass_2}", f"ntp trusted-key {ntp_key_2}",
"ntp authenticate", f"ntp server {ntp_ip_2} key {ntp_key_2}"])

###USER AGREEMENT AND LAST RESORT###
banner_cfg = (["banner login *\nYou are accessing a U.S. Government (USG) Information System (IS) that is provided "
"for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), "
"you consent to the following conditions:\n-The USG routinely intercepts and monitors "
"communications on this IS for purposes including, but not limited to, penetration testing, "
"COMSEC monitoring, network operations and defense,\npersonnel misconduct (PM), law enforcement "
"(LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize "
"data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are "
"subject to routine monitoring, interception, and search, and may be disclosed or used for any USG "
"authorized purpose.\n-This IS includes security measures (e.g., authentication and access "
"controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding "
"the above, using this IS does not constitute consent to PM, LE, or CI investigative searching or "
"monitoring of the content of privileged communications, or work product,\nrelated to personal "
"representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such "
"communications and work product are private and confidential. See User Agreement "
"for details.\n*\n"])
last_cfg_cmd_1 = (["no username cisco", "no username admin", f"username {last_user} privilege 15 secret 0 {last_pass}"])

###ENABLE SECRET###
secret_cfg_cmd_1 = ([f"enable secret 0 {secret_pass}"])

###AAA###
aaa_cfg_cmd_1 = (["aaa new-model", f"aaa authentication login default group {rad_tac_1} local",
f"{rad_tac_1}-server host {aaa_ip_1} key {aaa_key_1}", ])
aaa_cfg_cmd_2 = (["aaa new-model", f"aaa authentication login default group {rad_tac_2} local",
f"{rad_tac_2}-server host {aaa_ip_2} key {aaa_key_2}", ])

###VLAN 1 CHECKS###
vlan_disable_cmd = (["vlan 1", "shutdown", "interface vlan 1", "shutdown"])




###Start timer for for loop###
start_time = time.time()
for host in ip_list:
    host = host.strip()
    net_connect = netmiko.ConnectHandler(device_type='cisco_ios', ip=host, username=username, password=password,
                                         secret=secret)
    net_connect.enable()
    ###INITIAL CFG SAVES###
    # There should be a .txt file for each IP address specified in the ip_list file; these .txt files will be the
    # original config prior to STIG checking and resulting changes.
    initial = sys.stdout
    sys.stdout = open(f"DESIRED PATH OF INITIAL CFG \\{host}_initial_cfg.txt", "w")
    write_config = net_connect.send_command("show run")
    sys.stdout.write(write_config)
    sys.stdout.close()
    sys.stdout = initial
    ###VTY LINES###
    vty_protections = net_connect.send_config_set(vty_cfg_cmd)
    ###LOGGING###
    log_protections_1 = net_connect.send_config_set(log_1_cfg_cmd)
    if log_ip_2 is None:
        pass
    else:
        log_protections_2 = net_connect.send_config_set(log_2_cfg_cmd)
    ###SERVICES###
    svc_disabled = net_connect.send_config_set(svc_dis_cfg_cmd)
    svc_enabled = net_connect.send_config_set(svc_en_cfg_cmd)
    ###SSH###
    ssh_cfg = net_connect.send_config_set(ssh_cfg_cmd)
    ###NTP###
    ntp_cfg_1 = net_connect.send_config_set(ntp_cfg_cmd_1)
    if ntp_ip_2 is None:
        pass
    else:
        ntp_cfg_2 = net_connect.send_config_set(ntp_cfg_cmd_2)
    ###USER AGREEMENT AND LAST RESORT###
    banner_cfg_1 = net_connect.send_config_set(banner_cfg)
    last_resort_cfg = net_connect.send_config_set(last_cfg_cmd_1)
    secret_cfg = net_connect.send_config_set(secret_cfg_cmd_1)
    ###AAA###
    aaa_cfg_1 = net_connect.send_config_set(aaa_cfg_cmd_1)
    if aaa_ip_2 is None:
        pass
    else:
        aaa_cfg_2 = net_connect.send_config_set(aaa_cfg_cmd_2)
    print("Non-VLAN Commands took", round(time.time() - start_time, 2), "seconds to run\n")
    ###VLAN 1 CHECKS###
    vlan_disable = net_connect.send_config_set(vlan_disable_cmd)
    vlan1_check = net_connect.send_command("show vlan", use_textfsm=True)
    for each_vlan in vlan1_check:
        vlan_status = each_vlan['vlan_id']
        if vlan_status == "1":
            vlan_name = each_vlan["interfaces"]
            for each_interface in vlan_name:
                net_connect.send_config_set([f"interface {each_interface}", "shutdown"], delay_factor=4)
                print(f"Interface {each_interface} has been disabled due to being in VLAN 1.")
    ###UNUSED VLAN###
    open_unused_vlan = net_connect.send_config_set([f"vlan {unused_vlan}", "no shutdown"])
    disabled_check = net_connect.send_command("show int status", use_textfsm=True)
    ###SET ALL NOTCONNECT/DISABLED IN UNUSED VLAN, DISABLE TRUNKING###
    for each_port in disabled_check:
        interface_status = each_port["status"]
        if interface_status == "disabled" or interface_status == "notconnect":
            interface_name = each_port["port"]
            net_connect.send_config_set(
                [f"interface {interface_name}", "switchport mode access", "switchport nonegotiate",
                 f"switchport access vlan {unused_vlan}", "no switchport mode trunk",
                 "no switchport trunk native vlan", "no switchport trunk encapsulation dot1q",
                 "switchport port-security", "switchport port-security mac-address sticky"],
                delay_factor=4)
    ###NATIVE VLAN###
    net_connect.send_config_set([f"vlan {native_vlan}", "no shutdown"])
    trunk_check = net_connect.send_command("show int status", use_textfsm=True)
    ###SET NATIVE VLAN AND REMOVE VLAN1 FROM TRUNK###
    for each_trunk in trunk_check:
        vlan_status = each_trunk["vlan"]
        if vlan_status == "trunk":
            trunk_name = each_trunk["port"]
            net_connect.send_config_set([f"interface {trunk_name}", f"switchport trunk native vlan {native_vlan}",
                                         "switchport trunk allowed vlan remove 1"])
    ###SET PORT SECURITY FOR ALL NON-ROUTED, NON-TRUNK PORTS###
    port_sec_check = net_connect.send_command("show int status", use_textfsm=True)
    for each_access in port_sec_check:
        not_trunk_status = each_access["vlan"]
        if not_trunk_status != "trunk" or not_trunk_status != "routed":
            access_name = each_access["port"]
            net_connect.send_config_set([f"interface {access_name}", "switchport port-security",
                                         "switchport port-security mac-address sticky"], delay_factor=4)
    ###WRITE CONFIG###
    net_connect.send_command("wr")
    ###ENDING CFG###
    ending = sys.stdout
    sys.stdout = open(f"DESIRED PATH OF FINISHED CFG \\{host}_ending_cfg.txt", "w")
    write_final_config = net_connect.send_command("show run")
    sys.stdout.write(write_final_config)
    sys.stdout.close()
    sys.stdout = ending
    print("All commands took", round(time.time() - start_time, 2), "seconds to run\n")

ip_list.close()