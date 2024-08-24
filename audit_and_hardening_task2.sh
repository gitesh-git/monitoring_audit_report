#!/bin/bash

# Configuration File for Custom Security Checks
CONFIG_FILE="/etc/audit_config.conf"

#1 Function: User and Group Audits
user_group_audit() {
    echo "=== User and Group Audit ==="
    # List all users and groups
    echo "Users:"
    awk -F: '{ print $1 }' /etc/passwd
    echo "Groups:"
    awk -F: '{ print $1 }' /etc/group

    # Check for users with UID 0
    echo "Users with UID 0:"
    awk -F: '($3 == 0) { print $1 }' /etc/passwd

    # Check for users without passwords or with weak passwords
    echo "Users without passwords or with weak passwords:"
    awk -F: '($2 == "" || $2 == "*" || $2 == "!" ) { print $1 " has no password or weak password" }' /etc/shadow
    echo
}

#2 Function: File and Directory Permissions Audit
file_permissions_audit() {
    echo "=== File and Directory Permissions Audit ==="
    
    # Scan for world-writable files and directories
    echo "World-writable files and directories:"
    find / -xdev -type f -perm -0002 -ls 2>/dev/null
    find / -xdev -type d -perm -0002 -ls 2>/dev/null
    
    # Check SSH directories and permissions
    echo "SSH directories with insecure permissions:"
    find /home -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null
    
    # Report files with SUID/SGID bits set
    echo "Files with SUID/SGID bits set:"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} \; 2>/dev/null
    echo
}

#3 Function: Service Audits
service_audit() {
    echo "=== Service Audit ==="

    # List all running services
    echo "Running services:"
    systemctl list-units --type=service --state=running

    # Check for unauthorized services
    echo "Unauthorized services:"
    for service in apache2 httpd mysql; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    done

    # Check critical services
    echo "Critical services status:"
    for service in sshd iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running"
    done

    # Check for services on non-standard or insecure ports
    echo "Services listening on non-standard or insecure ports:"
    netstat -tuln | grep -Ev '(:22|:80|:443|:53)'
    echo
}

#4 Function: Firewall and Network Security
firewall_network_audit() {
    echo "=== Firewall and Network Security Audit ==="

    # Verify that a firewall is active
    echo "Firewall status:"
    systemctl is-active --quiet ufw && echo "UFW is active" || echo "UFW is not active"
    systemctl is-active --quiet iptables && echo "iptables is active" || echo "iptables is not active"

    # Report open ports
    echo "Open ports and associated services:"
    netstat -tuln

    # Check for IP forwarding and insecure network configurations
    echo "IP forwarding status:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding

    echo "Other insecure network configurations:"
    sysctl -a | grep '\.accept_source_route'
    echo
}

#5 Function: IP and Network Configuration Checks
ip_network_config_check() {
    echo "=== IP and Network Configuration Checks ==="

    # Identify public vs. private IPs
    echo "IP addresses:"
    ip -4 addr show | grep inet | awk '{print $2}' | while read ip; do
        echo "$ip"
        if [[ $ip =~ ^10\.|^172\.16\.|^192\.168\. ]]; then
            echo "Private IP"
        else
            echo "Public IP"
        fi
    done

    # Ensure sensitive services are not exposed on public IPs
    echo "Checking for sensitive services exposed on public IPs:"
    netstat -tuln | grep '0.0.0.0:22'
    echo
}

#6 Function: Security Updates and Patching
security_updates_check() {
    echo "=== Security Updates and Patching ==="

    # Check for available security updates
    echo "Checking for security updates:"
    apt-get update && apt-get --just-print upgrade

    # Ensure automatic updates are configured
    echo "Checking if unattended-upgrades is installed and enabled:"
    dpkg -l | grep unattended-upgrades
    systemctl is-enabled --quiet unattended-upgrades && echo "unattended-upgrades is enabled" || echo "unattended-upgrades is not enabled"
    echo
}

#7 Function: Log Monitoring
log_monitoring() {
    echo "=== Log Monitoring ==="

    # Check for suspicious log entries
    echo "Suspicious log entries in auth.log:"
    grep "Failed password" /var/log/auth.log | tail -n 10
    grep "Accepted publickey" /var/log/auth.log | tail -n 10
    echo
}

#8 Function: Server Hardening Steps
server_hardening() {
    echo "=== Server Hardening Steps ==="

    # SSH Configuration Hardening
    echo "Configuring SSH for key-based authentication and disabling root password login:"
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    systemctl reload sshd

    # Disabling IPv6 if not required
    echo "Disabling IPv6:"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -p

    # Securing the Bootloader
    #echo "Securing the GRUB bootloader:"
    #grub-mkpasswd-pbkdf2 | sed -n 's/^grub.pbkdf2.*=//p' | xargs -I {} echo "set superusers='root'\npassword_pbkdf2 root {}" >> /etc/grub.d/40_custom
    #update-grub

    # Configuring firewall rules
    echo "Configuring firewall rules:"
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4

    # Enabling automatic security updates
    echo "Enabling automatic security updates:"
    dpkg-reconfigure -plow unattended-upgrades
    echo
}

#9 Function: Custom Security Checks
custom_security_checks() {
    echo "=== Custom Security Checks ==="

    if [ -f "$CONFIG_FILE" ]; then
        echo "Running custom security checks defined in $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        echo "No custom security checks defined."
    fi
    echo
}

#10 Function: Reporting and Alerting
generate_report() {
    REPORT_FILE="/var/log/audit_report_$(date +%Y%m%d%H%M%S).log"
    echo "Generating audit and hardening report at $REPORT_FILE"
    exec > >(tee -a $REPORT_FILE) 2>&1

    user_group_audit
    file_permissions_audit
    service_audit
    firewall_network_audit
    ip_network_config_check
    security_updates_check
    log_monitoring
    server_hardening
    custom_security_checks

    echo "audit and hardening process complete. Report generated at $REPORT_FILE"
}

# Main script execution
generate_report
