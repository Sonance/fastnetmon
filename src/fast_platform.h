#pragma once

// This file automatically generated for your platform (Linux, FreeBSD and others) with cmake

class FastnetmonPlatformConfigurtion {
    public:

    /* Platform specific paths */
    std::string fastnetmon_version = "1.2.0 master git-292d0c3792e9ac08dac0060deb5820e8af5dd12b";

    std::string pid_path = "/var/run/fastnetmon.pid";
    std::string global_config_path = "/etc/fastnetmon.conf";

    std::string log_file_path = "/var/log/fastnetmon.log";
    std::string attack_details_folder = "/var/log/fastnetmon_attacks";

    // Default path to notify script
    std::string notify_script_path = "/usr/local/bin/notify_about_attack.sh";

    // Default path to file with networks for whitelising
    std::string white_list_path = "/etc/networks_whitelist";

    // Default path to file with all networks listing
    std::string networks_list_path = "/etc/networks_list";

    /* Platform specific paths end */
};
