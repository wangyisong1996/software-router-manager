const config = {
    host: "127.0.0.1",
    port: 3000,
    session_secret: "secret-123",
    session_max_age: 86400 * 1000,
    web_password: "password",
    network_interface: "eth0",
    dhcp_config_file: "/etc/router-config/dhcp.conf",
};

module.exports = config;
