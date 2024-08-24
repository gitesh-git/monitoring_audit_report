#!/bin/bash

#1 Function to display the top 10 most used applications by CPU and memory
show_top_applications() {
    echo "Top 10 Applications by CPU and Memory Usage:"
    ps aux --sort=-%cpu,-%mem | awk 'NR<=11{print $1, $2, $3, $4, $11}' | column -t
    echo
}

#2 Function to display network monitoring details
show_network_monitoring() {
    echo "Network Monitoring:"
    netstat -tn | grep ESTABLISHED | wc -l | awk '{print "Concurrent Connections: "$1}'
    netstat -i | awk '/^[a-zA-Z]/ {iface=$1} /[0-9]+\s+[0-9]+\s+[0-9]+/ {print iface ": " "Packet Drops: In="$4 ", Out="$8}'
    ifconfig | grep 'RX packets' | awk '{print $1, $2}' | awk -F: '{print "MB In: "$2/1024/1024 " MB"}'
    ifconfig | grep 'TX packets' | awk '{print $1, $2}' | awk -F: '{print "MB Out: "$2/1024/1024 " MB"}'
    echo
}

#3 Function to display disk usage
show_disk_usage() {
    echo "Disk Usage:"
    df -h | awk '$5+0 > 80 {print $1 ": " $5 " used (Alert)"} $5+0 <= 80 {print $1 ": " $5 " used"}'
    echo
}

#4 Function to display system load
show_system_load() {
    echo "System Load:"
    uptime | awk -F'load average:' '{print "Load Average:" $2}'
    mpstat | awk '$12 ~ /[0-9.]+/ {print "CPU Usage: User=" $3 "% System=" $5 "% Idle=" $12 "%"}'
    echo
}

#5 Function to display memory usage
show_memory_usage() {
    echo "Memory Usage:"
    free -h | awk '/^Mem:/ {print "Total Memory: " $2 ", Used: " $3 ", Free: " $4}'
    free -h | awk '/^Swap:/ {print "Total Swap: " $2 ", Used: " $3 ", Free: " $4}'
    echo
}

#6 Function to display process monitoring details
show_process_monitoring() {
    echo "Process Monitoring:"
    ps -e | wc -l | awk '{print "Total Active Processes: "$1}'
    ps aux --sort=-%cpu,-%mem | awk 'NR<=6{print $1, $2, $3, $4, $11}' | column -t
    echo
}

#7 Function to display service monitoring status
show_service_monitoring() {
    echo "Service Monitoring:"
    for service in sshd nginx apache2 iptables; do
        systemctl is-active --quiet $service && echo "$service: Running" || echo "$service: Not Running"
    done
    echo
}

#8 Function to display the full dashboard
show_dashboard() {
    clear
    echo "=== System Monitoring Dashboard ==="
    show_top_applications
    show_network_monitoring
    show_disk_usage
    show_system_load
    show_memory_usage
    show_process_monitoring
    show_service_monitoring
}

# Parse command-line switches to display specific sections
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -cpu) show_top_applications ;;
        -network) show_network_monitoring ;;
        -disk) show_disk_usage ;;
        -load) show_system_load ;;
        -memory) show_memory_usage ;;
        -process) show_process_monitoring ;;
        -services) show_service_monitoring ;;
        -dashboard) show_dashboard; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done
