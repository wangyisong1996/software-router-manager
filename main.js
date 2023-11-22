const express = require("express");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cookieSession = require("cookie-session");
const minify = require("html-minifier").minify;
const marked = require("marked").marked;
const fs = require("fs");
const fsp = fs.promises;
const config = require("./config");
const utils = require("./utils");

const app = express();

// morgan
app.set("trust proxy", true);
app.use(morgan("combined"));

// body-parser
app.use(bodyParser.urlencoded({ extended: false }));

// static
app.use(express.static("static"));

// ejs
app.set("view engine", "ejs");
app.set("views", "views");
app.use((_, res, next) => {
    res.locals.vars = {
        show_menu: true,
    };
    res.locals.marked = marked;
    next();
});

// minify
app.use((req, res, next) => {
    const orig_render = res.render;
    res.render = (view) => {
        orig_render.call({ req, res, next }, view, res.locals, (err, html) => {
            if (err) {
                next(err);
            } else {
                res.send(minify(html, {
                    collapseWhitespace: true,
                    removeComments: true,
                }));
            }
        });
    };

    next();
});

// cookie session
app.use(cookieSession({
    name: "router-management",
    secret: config.session_secret,
    maxAge: config.session_max_age,
}));

// routes (public)
app.get("/login", async (_, res) => {
    const vars = res.locals.vars;
    vars.title = "Please Login";
    vars.content_title = "Please Login";
    vars.show_menu = false;

    res.render("login");
});

app.post("/api/login", (req, res) => {
    if (req.body.password === config.web_password) {
        req.session.login = true;
        res.json({ ok: true });
    } else {
        res.json({ ok: false, error: "Wrong password" });
    }
});

// check login
app.use((req, res, next) => {
    if (req.session.login) {
        next();
    } else {
        res.redirect("/login");
    }
});

// routes (private)
app.get("/logout" , async (req, res) => {
    req.session = null;
    res.redirect("/login");
});

app.get("/", async (_, res) => {
    const vars = res.locals.vars;
    vars.title = "Home";
    vars.content_title = "Router Management";

    const run = async (f) => {
        try {
            await f();
        } catch (e) {
            if (!vars.error) {
                vars.error = e.stack;
            } else {
                vars.error += "\n\n" + e.stack;
            }
        }
    };

    vars.server_uptime = process.uptime();
    await run(async () => { vars.system_uptime = (await utils.system("uptime")).stdout.trim(); });
    await run(async () => { vars.cpu_info = (await utils.system("lscpu")).stdout.trim(); });

    vars.md_to_render_begin = [
        "## System Status",
        "",
        `* Server uptime: \`${vars.server_uptime}\``,
        `* System uptime: \`${vars.system_uptime}\``,
        "",
        "## CPU Info",
        "",
        "```",
        vars.cpu_info,
        "```",
    ].join("\n");

    res.render("index");
});

const compare_ip = (a, b) => {
    const a1 = a.split(".").map(x => parseInt(x));
    const b1 = b.split(".").map(x => parseInt(x));
    for (let i = 0; i <= Math.min(a1.length, b1.length); i++) {
        if (a1[i] < b1[i]) {
            return -1;
        } else if (a1[i] > b1[i]) {
            return 1;
        }
    }
    return 0;
};

app.get("/devices", async (_, res) => {
    const vars = res.locals.vars;
    vars.title = "Online Devices";
    vars.content_title = "Online Devices";

    const netif = config.network_interface;

    try {
        // devices = (await utils.system(`arp -an | grep -v incomplete | grep ${netif} | awk '{print $2, $4}'`)).stdout.split("\n");
        const arp_out = (await utils.system("arp -an")).stdout.split("\n");
        vars.devices = arp_out.filter(x => (
            x.trim !== "" && !x.includes("incomplete") && x.includes(netif)
        )).map((line) => {
            const arr = line.split(" ");
            const ip = arr[1].slice(1, -1);
            const mac = arr[3];
            return { ip, mac };
        });
    } catch (e) {
        vars.devices = [];
        vars.error = e.stack;
    }

    vars.devices.sort((a, b) => {
        const cmp = compare_ip(a.ip, b.ip);
        if (cmp != 0) {
            return cmp;
        } else {
            return a.mac.localeCompare(b.mac);
        }
    });

    res.render("devices");
});

const get_dhcp_hosts = async () => {
    // host h_10_0_0_123 { hardware ethernet 00:00:00:00:00:00; fixed-address 10.0.0.123; } # name
    const dhcp_config = await fsp.readFile(config.dhcp_config_file, "utf-8");
    const hosts = dhcp_config.split("\n").filter(x => x.startsWith("host")).map((line) => {
        const arr = line.split("}")[0].split("{")[1].split(";");
        const ip = arr[1].split(" ").slice(-1)[0];
        const mac = arr[0].split(" ").slice(-1)[0].toLowerCase();
        const comment = line.split("#").slice(1).join("#").trim();
        return { ip, mac, comment };
    });

    hosts.sort((a, b) => {
        const cmp = compare_ip(a.ip, b.ip);
        if (cmp != 0) {
            return cmp;
        } else {
            return a.mac.localeCompare(b.mac);
        }
    });

    return hosts;
};

const save_dhcp_hosts = async (hosts) => {
    try {
        const hosts_sorted = hosts.slice();
        hosts_sorted.sort((a, b) => {
            const cmp = compare_ip(a.ip, b.ip);
            if (cmp != 0) {
                return cmp;
            } else {
                return a.mac.localeCompare(b.mac);
            }
        });

        const dhcp_config_old = await fsp.readFile(config.dhcp_config_file, "utf-8");
        const dhcp_config_new = hosts.map((host) => {
            return `host h_${host.ip.replace(/\./g, "_")} { hardware ethernet ${host.mac}; fixed-address ${host.ip}; } # ${host.comment}`;
        }).join("\n");
        await fsp.writeFile(config.dhcp_config_file, dhcp_config_new);

        try {
            await utils.system("dhcpd -t");
            await utils.system("sudo service isc-dhcp-server restart");
        } catch (e) {
            await fsp.writeFile(config.dhcp_config_file, dhcp_config_old);
            throw e;
        }
    } catch (e) {
        throw e;
    }
};

app.get("/dhcp", async (_, res) => {
    const vars = res.locals.vars;
    vars.title = "Static DHCP Config";
    vars.content_title = "Static DHCP Config";

    try {
        vars.hosts = await get_dhcp_hosts();
    } catch (e) {
        vars.hosts = [];
        vars.error = e.stack;
    }

    res.render("dhcp");
});

app.post("/api/dhcp/add", async (req, res) => {
    const { ip, mac, comment } = req.body;
    if (typeof ip !== "string" || typeof mac !== "string" || typeof comment !== "string") {
        res.json({ ok: false, error: "Invalid parameters" });
        return;
    }

    if (!/^((0|([1-9][0-9]{0,2}))\.){3}(0|([1-9][0-9]{0,2}))$/.test(ip)) {
        res.json({ ok: false, error: "Invalid IP" });
        return;
    }

    if (!/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(mac)) {
        res.json({ ok: false, error: "Invalid MAC" });
        return;
    }

    const mac_processed = mac.toLowerCase();
    const comment_processed = comment.replace(/[\r\n]/g, " ").trim();

    try {
        const hosts = await get_dhcp_hosts();
        const exists = hosts.find(x => x.ip === ip || x.mac === mac_processed);
        if (exists) {
            res.json({ ok: false, error: "IP or MAC already exists" });
            return;
        }

        hosts.push({ ip, mac: mac_processed, comment: comment_processed });
        await save_dhcp_hosts(hosts);
    } catch (e) {
        res.json({ ok: false, error: e.stack });
        return;
    }

    res.json({ ok: true });
});

app.post("/api/dhcp/delete", async (req, res) => {
    const { ip } = req.body;
    if (typeof ip !== "string") {
        res.json({ ok: false, error: "Invalid parameters" });
        return;
    }

    if (!/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(ip)) {
        res.json({ ok: false, error: "Invalid IP" });
        return;
    }

    try {
        const hosts = await get_dhcp_hosts();
        const exists = hosts.find(x => x.ip === ip);
        if (!exists) {
            res.json({ ok: false, error: "IP not exists" });
            return;
        }

        const hosts_new = hosts.filter(x => x.ip !== ip);
        await save_dhcp_hosts(hosts_new);
    } catch (e) {
        res.json({ ok: false, error: e.stack });
        return;
    }

    res.json({ ok: true });
});

const sort_port_forwarding_rules = (rules) => {
    const ret = rules.slice();
    ret.sort((a, b) => {
        let r;
        r = parseInt(a.public_port) - parseInt(b.public_port);
        if (r != 0) return r;
        r = a.protocol.localeCompare(b.protocol);
        if (r != 0) return r;
        r = compare_ip(a.private_ip, b.private_ip);
        if (r != 0) return r;
        r = parseInt(a.private_port) - parseInt(b.private_port);
        if (r != 0) return r;
        r = a.comment.localeCompare(b.comment);
        return r;
    });
    return ret;
};

const get_port_forwarding_rules = async () => {
    // -A PREROUTING -p tcp -m tcp --dport 12345 -j DNAT --to-destination 10.0.0.123:12345
    // -A PREROUTING -p tcp -m tcp --dport 12345 -m comment --comment "" -j DNAT --to-destination 10.0.0.123:12345
    const iptables_out = (await utils.system("sudo iptables -t nat -S")).stdout.split("\n");
    const rules = iptables_out.filter(x => x.startsWith("-A PREROUTING")).map((line) => {
        const arr = line.split(" ");
        const protocol = arr[3];
        const public_port = arr[7];
        const has_comment = arr[8] === "-m" && arr[9] === "comment";
        let comment_raw = "";
        let comment_processed = "";
        if (has_comment) {
            if (!arr[11].startsWith(`"`)) {
                arr[11] = `"` + arr[11] + `"`;
            }
            for (let i = 11; i < arr.length; i++) {
                if (arr[i].endsWith(`"`) && !arr[i].endsWith(`\\"`)) {
                    comment_processed = arr.slice(11, i + 1).join(" ").slice(1, -1);
                    comment_raw = comment_processed.replace(/\\"/g, `"`).replace(/\\\\/g, `\\`);
                    break;
                }
            }
        }
        const [private_ip, private_port] = line.split("-j DNAT --to-destination").slice(-1)[0].trim().split(":");
        return { protocol, public_port, private_ip, private_port, comment_processed, comment_raw };
    });

    return sort_port_forwarding_rules(rules);
};

app.get("/port-forwarding", async (_, res) => {
    const vars = res.locals.vars;
    vars.title = "Port Forwarding Rules";
    vars.content_title = "Port Forwarding Rules";

    try {
        vars.rules = await get_port_forwarding_rules();
    } catch (e) {
        vars.rules = [];
        vars.error = e.stack;
    }

    res.render("port-forwarding");
});

const parse_port_forwarding_rule_body = (body) => {
    const { protocol, public_port, private_ip, private_port, comment } = body;
    if (typeof protocol !== "string" || typeof public_port !== "string" || typeof private_ip !== "string" || typeof private_port !== "string" || typeof comment !== "string") {
        throw { ok: false, error: "Invalid parameters" };
    }

    if (!["tcp", "udp"].includes(protocol)) {
        throw { ok: false, error: "Invalid protocol" };
    }

    if (!/^[1-9][0-9]{0,4}$/.test(public_port)) {
        throw { ok: false, error: "Invalid public port" };
    }

    if (!/^((0|([1-9][0-9]{0,2}))\.){3}(0|([1-9][0-9]{0,2}))$/.test(private_ip)) {
        throw { ok: false, error: "Invalid private IP" };
    }

    if (!/^[1-9][0-9]{0,4}$/.test(private_port)) {
        throw { ok: false, error: "Invalid private port" };
    }

    const comment_raw = comment.replace(/[\r\n]/g, " ").trim();
    const comment_processed = comment_raw.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
    return { protocol, public_port, private_ip, private_port, comment_processed, comment_raw };
}

app.post("/api/port-forwarding/add", async (req, res) => {
    let rule;
    try {
        rule = parse_port_forwarding_rule_body(req.body);
    } catch (e) {
        res.json(e);
        return;
    }

    try {
        const rules = await get_port_forwarding_rules();
        const exists = rules.find(x => x.public_port === rule.public_port && x.protocol === rule.protocol);
        if (exists) {
            res.json({ ok: false, error: "Rule already exists" });
            return;
        }

        const cmd = `sudo iptables -t nat -A PREROUTING -p ${rule.protocol} -m ${rule.protocol} --dport ${rule.public_port} -j DNAT --to-destination ${rule.private_ip}:${rule.private_port} -m comment --comment "${rule.comment_processed}" && sudo netfilter-persistent save`;
        await utils.system(cmd);
    } catch (e) {
        res.json({ ok: false, error: e.stack });
        return;
    }

    res.json({ ok: true });
});

app.post("/api/port-forwarding/delete", async (req, res) => {
    let rule;
    try {
        rule = parse_port_forwarding_rule_body(req.body);
    } catch (e) {
        res.json(e);
        return;
    }

    console.log(rule.comment_raw);

    try {
        const rules = await get_port_forwarding_rules();
        const exists = rules.find(x => x.public_port === rule.public_port && x.protocol === rule.protocol && x.private_ip === rule.private_ip && x.private_port === rule.private_port && x.comment_raw === rule.comment_raw);
        if (!exists) {
            res.json({ ok: false, error: "Rule not exists" });
            return;
        }

        const cmd = `sudo iptables -t nat -D PREROUTING -p ${rule.protocol} -m ${rule.protocol} --dport ${rule.public_port} -j DNAT --to-destination ${rule.private_ip}:${rule.private_port} -m comment --comment "${rule.comment_processed}" && sudo netfilter-persistent save`;
        await utils.system(cmd);
    } catch (e) {
        res.json({ ok: false, error: e.stack });
        return;
    }

    res.json({ ok: true });
});

// start server
app.listen(config.port, config.host, () => {
    console.log(`Server started at http://${config.host}:${config.port}`);
});
