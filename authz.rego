package docker.authz

default allow = false

allow {
    not deny
}

# CIS 5.3 Ensure that Linux kernel capabilities are restricted within containers (Scored)
deny {
    c_5_03_caps_not_dropped
}
c_5_03_caps_not_dropped {
    not drop_capabilities
}
drop_capabilities {
    caps := ["AUDIT_WRITE","CHOWN","DAC_OVERRIDE","FOWNER","FSETID","KILL","MKNOD","NET_BIND_SERVICE","NET_RAW","SETFCAP","SETGID","SETPCAP","SETUID","SYS_CHROOT"]
    input.Body.HostConfig.CapDrop == caps
    input.Body.HostConfig.CapAdd ==  null
}

# CIS 5.4 Ensure that privileged containers are not used (Scored)
# CIS 5.22 Ensure that docker exec commands are not used with the privileged option (Scored)
deny {
    c_5_04_privileged_container
}
c_5_04_privileged_container {
    input.Body.HostConfig.Privileged == true
}

# CIS 5.5 Ensure sensitive host system directories are not mounted on containers (Scored)
deny {
  c_5_05_sensitive_binds
}
c_5_05_sensitive_binds {
    input.Body.HostConfig.Mounts[_].Source == "/"
}
c_5_05_sensitive_binds {
    paths = ["/boot","/dev","/etc","/lib","/proc","/sys","/usr"]
    startswith(input.Body.HostConfig.Mounts[_].Source, paths[_])
}
c_5_05_sensitive_binds {
    paths = ["/:","/boot","/dev","/etc","/lib","/proc","/sys","/usr"]
    startswith(input.Body.HostConfig.Binds[_], paths[_])
}

# CIS 5.7 Ensure privileged ports are not mapped within containers (Scored)
deny {
    c_5_07_privileged_ports
}
c_5_07_privileged_ports {
    to_number(input.Body.HostConfig.PortBindings[_][_].HostPort) <= 1024
}

# CIS 5.8 Ensure that only needed ports are open on the container (Not Scored)
deny {
  c_5_08_all_ports_published
}
c_5_08_all_ports_published {
   input.Body.HostConfig.PublishAllPorts == true
}

# CIS 5.9 Ensure that the host's network namespace is not shared (Scored)
deny {
  c_5_09_host_network_shared
}
c_5_09_host_network_shared {
    input.Body.HostConfig.NetworkMode == "host"
}

# CIS 5.10 Ensure that the memory usage for containers is limited (Scored)
deny {
  c_5_10_unlimited_memory
}
c_5_10_unlimited_memory {
    input.Body.HostConfig.Memory <= 0
}

# CIS 5.11 Ensure that CPU priority is set appropriately on containers (Scored)
deny {
  c_5_11_unlimited_cpu
}
c_5_11_unlimited_cpu {
    input.Body.HostConfig.CpuShares <= 0
}
c_5_11_unlimited_cpu {
    input.Body.HostConfig.CpuShares >= 1024
}

# CIS 5.12 Ensure that the container's root filesystem is mounted as read only (Scored)
deny {
    c_5_12_rootfs_mounted_rw
}
c_5_12_rootfs_mounted_rw {
    input.Body.HostConfig.ReadonlyRootfs == false
}

# CIS 5.13 Ensure that incoming container traffic is bound to a specific host interface (Scored)
deny {
    c_5_13_default_interface_used
}
c_5_13_default_interface_used {
    input.Body.HostConfig.PortBindings[_][_].HostIp == "0.0.0.0"
}
c_5_13_default_interface_used {
    count(input.Body.HostConfig.PortBindings[_]) == 0
}
c_5_13_default_interface_used {
    ips := [ ip | input.Body.HostConfig.PortBindings[i][j].HostPort != ""; not input.Body.HostConfig.PortBindings[i][j].HostIp; ip := "default" ]
    trace(ips[_])
    ips[_] == "default"
}

# CIS 5.14 Ensure that the 'on-failure' container restart policy is set to '5' (Scored)
deny {
    c_5_14_restart_onfailure_not_configured
}
c_5_14_restart_onfailure_not_configured {
    input.Body.HostConfig.RestartPolicy.Name != "on-failure"
}
c_5_14_restart_onfailure_not_configured {
    input.Body.HostConfig.RestartPolicy.MaximumRetryCount != 5
}

# CIS 5.15 Ensure that the host's process namespace is not shared (Scored)
deny {
    c_5_15_host_process_namespace_shared
}
c_5_15_host_process_namespace_shared {
    input.Body.HostConfig.PidMode == "host"
}

# CIS 5.16 Ensure that the host's IPC namespace is not shared (Scored)
deny {
   c_5_15_host_ipc_namespace_shared
}
c_5_15_host_ipc_namespace_shared {
    input.Body.HostConfig.IpcMode == "host"
}

# CIS 5.17 Ensure that host devices are not directly exposed to containers (Not Scored)
deny {
    c_5_17_host_devices_exposed
}
c_5_17_host_devices_exposed {
    count(input.Body.HostConfig.Devices)>0
}

#CIS 5.19 Ensure mount propagation mode is not set to shared (Scored)
deny {
    c_5_19_mount_propagation_shared
}
c_5_19_mount_propagation_shared {
    input.Body.HostConfig.Mounts[_].BindOptions.Propagation == "shared"
}
c_5_19_mount_propagation_shared {
    input.Body.HostConfig.Mounts[_].BindOptions.Propagation == "rshared"
}
c_5_19_mount_propagation_shared {
    bind := split(input.Body.HostConfig.Binds[_],":")
    options := split(bind[_],",")
    options[_] == "shared"
}
c_5_19_mount_propagation_shared {
    bind := split(input.Body.HostConfig.Binds[_],":")
    options := split(bind[_],",")
    options[_] == "rshared"
}

# CIS 5.20 Ensure that the host's UTS namespace is not shared (Scored)
deny {
    c_5_20_host_uts_namespace_shared
}
c_5_20_host_uts_namespace_shared {
    input.Body.HostConfig.UTSMode == "host"
}

# CIS 5.21 Ensure the default seccomp profile is not Disabled (Scored)
deny {
    c_5_21_seccomp_unconfined
}
c_5_21_seccomp_unconfined {
    input.Body.HostConfig.SecurityOpt[_] == "seccomp:unconfined"
}

# CIS 5.23 Ensure that docker exec commands are not used with the user=root option (Not Scored)
deny {
    c_5_23_exec_user_root
}
c_5_23_exec_user_root {
    input.Body.User == "root"
}

# CIS 5.24 Ensure that cgroup usage is confirmed (Scored)
deny {
  c_5_24_custom_cgroup_parent
}
c_5_24_custom_cgroup_parent {
    input.Body.HostConfig.CgroupParent != ""
}

# CIS 5.25 Ensure that the container is restricted from acquiring additional privileges (Scored)
deny {
    c_5_25_new_privileges_not_restricted
}
c_5_25_new_privileges_not_restricted {
    not new_privileges
}
new_privileges {
    input.Body.HostConfig.SecurityOpt[_] == "no-new-privileges"
}

# CIS 5.28 Ensure that the PIDs cgroup limit is used (Scored)
deny {
  c_5_28_bad_pids_limit
}
c_5_28_bad_pids_limit {
    input.Body.HostConfig.PidsLimit > 1000
}
c_5_28_bad_pids_limit {
    input.Body.HostConfig.PidsLimit < 10
}

# CIS 5.29 Ensure that Docker's default bridge "docker0" is not used (Not Scored)
deny {
    c_5_29_default_network_used
}
c_5_29_default_network_used {
    count(input.Body.NetworkingConfig.EndpointsConfig) == 0
}

# CIS 5.30 Ensure that the host's user namespaces are not shared (Scored)
deny {
  c_5_30_host_user_namespace_shared
}
c_5_30_host_user_namespace_shared {
    input.Body.HostConfig.UsernsMode == "host"
}