config_file_path = "./out/.config"  # 修改为您的 .config 文件路径

def read_config_file(filename):
    config_options = set()
    with open(filename, "r") as f:
        for line in f:
            if line.startswith("CONFIG_"):
                option = line.strip().split("=")[0]
                config_options.add(option)
    return config_options

def main():
    missing_options = []

    required_options = [
        "CONFIG_NAMESPACES", "CONFIG_NET_NS", "CONFIG_PID_NS", "CONFIG_IPC_NS",
        "CONFIG_UTS_NS", "CONFIG_CGROUPS", "CONFIG_CGROUP_CPUACCT", "CONFIG_CGROUP_DEVICE",
        "CONFIG_CGROUP_FREEZER", "CONFIG_CGROUP_SCHED", "CONFIG_CPUSETS", "CONFIG_MEMCG",
        "CONFIG_KEYS", "CONFIG_VETH", "CONFIG_BRIDGE", "CONFIG_BRIDGE_NETFILTER",
        "CONFIG_IP_NF_FILTER", "CONFIG_IP_NF_TARGET_MASQUERADE",
        "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE", "CONFIG_NETFILTER_XT_MATCH_CONNTRACK",
        "CONFIG_NETFILTER_XT_MATCH_IPVS", "CONFIG_NETFILTER_XT_MARK", "CONFIG_IP_NF_NAT",
        "CONFIG_NF_NAT", "CONFIG_POSIX_MQUEUE", "CONFIG_CGROUP_BPF",
        # ... 添加剩余的项 ...
    ]

    optional_options = [
        "CONFIG_USER_NS", "CONFIG_SECCOMP", "CONFIG_SECCOMP_FILTER", "CONFIG_CGROUP_PIDS",
        "CONFIG_MEMCG_SWAP", "CONFIG_BLK_CGROUP", "CONFIG_BLK_DEV_THROTTLING",
        "CONFIG_CGROUP_PERF", "CONFIG_CGROUP_HUGETLB", "CONFIG_NET_CLS_CGROUP",
        "CONFIG_CGROUP_NET_PRIO", "CONFIG_CFS_BANDWIDTH", "CONFIG_FAIR_GROUP_SCHED",
        "CONFIG_IP_NF_TARGET_REDIRECT", "CONFIG_IP_VS", "CONFIG_IP_VS_NFCT",
        "CONFIG_IP_VS_PROTO_TCP", "CONFIG_IP_VS_PROTO_UDP", "CONFIG_IP_VS_RR",
        "CONFIG_SECURITY_SELINUX", "CONFIG_SECURITY_APPARMOR",
        "CONFIG_EXT3_FS", "CONFIG_EXT3_FS_XATTR", "CONFIG_EXT3_FS_POSIX_ACL",
        "CONFIG_EXT3_FS_SECURITY", "CONFIG_EXT4_FS", "CONFIG_EXT4_FS_POSIX_ACL",
        "CONFIG_EXT4_FS_SECURITY",
        # Network Drivers
        "CONFIG_VXLAN", "CONFIG_BRIDGE_VLAN_FILTERING",
        # Optional (for encrypted networks):
        "CONFIG_CRYPTO", "CONFIG_CRYPTO_AEAD", "CONFIG_CRYPTO_GCM", "CONFIG_CRYPTO_SEQIV",
        "CONFIG_CRYPTO_GHASH", "CONFIG_XFRM", "CONFIG_XFRM_USER", "CONFIG_XFRM_ALGO",
        "CONFIG_INET_ESP", "CONFIG_NETFILTER_XT_MATCH_BPF",
        "CONFIG_IPVLAN", "CONFIG_MACVLAN", "CONFIG_DUMMY",
        # Storage Drivers
        "CONFIG_BTRFS_FS", "CONFIG_BTRFS_FS_POSIX_ACL", "CONFIG_OVERLAY_FS",
        # ... 添加剩余的项 ...
    ]

    # 读取 .config 文件中的配置项
    config_options = read_config_file(config_file_path)

    # 检查必要的选项
    for option in required_options:
        if option not in config_options:
            missing_options.append(option)

    # 检查可选的选项
    for option in optional_options:
        if option not in config_options:
            missing_options.append(option)

    # 输出不存在的选项
    if missing_options:
        print("Missing options:")
        for option in missing_options:
            print("- " + option)
    else:
        print("All required and optional options are present in the .config file.")


if __name__ == "__main__":
    main()
