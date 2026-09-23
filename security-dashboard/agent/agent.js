
const os = require("os");
const { exec } = require("child_process");

const SERVER_URL = "http://localhost:5000";
const AGENT_VERSION = "1.3.0";

const HEARTBEAT_INTERVAL = 30000;
const APPLICATION_SCAN_INTERVAL = 300000;

/* =========================================================
   RUN COMMAND
========================================================= */

function runCommand(command) {
    return new Promise((resolve) => {
        exec(
            command,
            {
                timeout: 15000,
                maxBuffer: 5 * 1024 * 1024,
            },
            (error, stdout, stderr) => {
                resolve({
                    success: !error,
                    output: (
                        stdout ||
                        stderr ||
                        error?.message ||
                        ""
                    ).trim(),
                });
            }
        );
    });
}

/* =========================================================
   FIREWALL CHECK
========================================================= */

async function checkFirewall() {
    if (process.platform !== "darwin") {
        return {
            status: "UNKNOWN",
            enabled: null,
            message: "Firewall check is currently implemented for macOS",
        };
    }

    const result = await runCommand(
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
    );

    const output = (result.output || "").toLowerCase();

    console.log("[Firewall]", result.output || "No firewall output");

    if (
        output.includes("state = 1") ||
        output.includes("firewall is enabled") ||
        output.includes("enabled")
    ) {
        return {
            status: "ENABLED",
            enabled: true,
            message: "macOS firewall is enabled",
        };
    }

    if (
        output.includes("state = 0") ||
        output.includes("firewall is disabled") ||
        output.includes("disabled")
    ) {
        return {
            status: "DISABLED",
            enabled: false,
            message: "macOS firewall is disabled",
        };
    }

    return {
        status: "UNKNOWN",
        enabled: null,
        message: "Unable to determine macOS firewall status",
    };
}

/* =========================================================
   TIME MACHINE BACKUP CHECK
========================================================= */

async function checkBackup() {
    if (process.platform !== "darwin") {
        return {
            status: "UNKNOWN",
            enabled: null,
            message: "Backup check is currently implemented for macOS",
        };
    }

    const destination = await runCommand(
        "/usr/bin/tmutil destinationinfo"
    );

    const destinationOutput =
        (destination.output || "").toLowerCase();

    console.log(
        "[Backup Destination]",
        destination.output || "No destination information"
    );

    if (
        destinationOutput.includes("no destinations configured") ||
        destinationOutput.includes("no destinations")
    ) {
        return {
            status: "DISABLED",
            enabled: false,
            message: "No Time Machine backup destination configured",
        };
    }

    if (
        destination.success &&
        destination.output.length > 0
    ) {
        return {
            status: "ENABLED",
            enabled: true,
            message: "Time Machine backup destination configured",
        };
    }

    const backupStatus = await runCommand(
        "/usr/bin/tmutil status"
    );

    const backupOutput =
        (backupStatus.output || "").toLowerCase();

    console.log(
        "[Backup Status]",
        backupStatus.output || "No backup status"
    );

    if (
        backupOutput.includes("running = 1") ||
        backupOutput.includes("running = true")
    ) {
        return {
            status: "ENABLED",
            enabled: true,
            message: "Time Machine backup is currently running",
        };
    }

    return {
        status: "UNKNOWN",
        enabled: null,
        message: "Unable to determine macOS backup status",
    };
}

/* =========================================================
   MICROSOFT DEFENDER CHECK
========================================================= */

async function checkMicrosoftDefender() {
    const result = await runCommand(
        "pgrep -ifl 'mdatp|Microsoft Defender'"
    );

    const output =
        (result.output || "").toLowerCase();

    if (
        result.success &&
        (
            output.includes("mdatp") ||
            output.includes("microsoft defender")
        )
    ) {
        return {
            status: "ENABLED",
            enabled: true,
            product: "Microsoft Defender for Endpoint",
            message: "Microsoft Defender for Endpoint detected",
        };
    }

    return null;
}

/* =========================================================
   CROWDSTRIKE CHECK
========================================================= */

async function checkCrowdStrike() {
    const result = await runCommand(
        "pgrep -ifl 'falcon|crowdstrike'"
    );

    const output =
        (result.output || "").toLowerCase();

    if (
        result.success &&
        (
            output.includes("falcon") ||
            output.includes("crowdstrike")
        )
    ) {
        return {
            status: "ENABLED",
            enabled: true,
            product: "CrowdStrike",
            message: "CrowdStrike Falcon process detected",
        };
    }

    return null;
}

/* =========================================================
   SOPHOS CHECK
========================================================= */

async function checkSophos() {
    const result = await runCommand(
        "pgrep -ifl 'sophos'"
    );

    const output =
        (result.output || "").toLowerCase();

    if (
        result.success &&
        output.includes("sophos")
    ) {
        return {
            status: "ENABLED",
            enabled: true,
            product: "Sophos",
            message: "Sophos endpoint process detected",
        };
    }

    return null;
}

/* =========================================================
   ANTIVIRUS CHECK
========================================================= */

async function checkAntivirus() {
    const defender =
        await checkMicrosoftDefender();

    if (defender) {
        return defender;
    }

    const crowdstrike =
        await checkCrowdStrike();

    if (crowdstrike) {
        return crowdstrike;
    }

    const sophos =
        await checkSophos();

    if (sophos) {
        return sophos;
    }

    return {
        status: "UNKNOWN",
        enabled: null,
        product: "No managed antivirus detected",
        message: "No supported managed antivirus product detected",
    };
}

/* =========================================================
   SECURITY INFORMATION
========================================================= */

async function getSecurityInfo() {
    const [
        firewall,
        backup,
        antivirus,
    ] = await Promise.all([
        checkFirewall(),
        checkBackup(),
        checkAntivirus(),
    ]);

    let overallStatus = "UNKNOWN";

    if (
        firewall.status === "DISABLED" ||
        backup.status === "DISABLED" ||
        antivirus.status === "DISABLED"
    ) {
        overallStatus = "AT RISK";
    } else if (
        firewall.status === "ENABLED" &&
        backup.status === "ENABLED" &&
        antivirus.status === "ENABLED"
    ) {
        overallStatus = "SECURE";
    }

    const messages = [
        antivirus.message,
        firewall.message,
        backup.message,
    ].filter(Boolean);

    return {
        antivirus,
        firewall,
        backup,
        overallStatus,
        message: messages.join(" | "),
        checkedAt: new Date().toISOString(),
    };
}

/* =========================================================
   MEMORY INFORMATION
========================================================= */

function getMemoryInfo() {
    const totalGB = Number(
        (
            os.totalmem() /
            1024 /
            1024 /
            1024
        ).toFixed(2)
    );

    const freeGB = Number(
        (
            os.freemem() /
            1024 /
            1024 /
            1024
        ).toFixed(2)
    );

    const usedGB = Number(
        (totalGB - freeGB).toFixed(2)
    );

    const usagePercent =
        totalGB > 0
            ? Number(
                (
                    (usedGB / totalGB) *
                    100
                ).toFixed(1)
            )
            : 0;

    return {
        totalGB,
        freeGB,
        usedGB,
        usagePercent,
    };
}

/* =========================================================
   CPU INFORMATION
========================================================= */

function getCPUInfo() {
    const cpus = os.cpus();

    const loadAverage =
        os.loadavg();

    return {
        model:
            cpus.length > 0
                ? cpus[0].model
                : "Unknown",

        cores:
            cpus.length,

        load1m:
            Number(loadAverage[0].toFixed(2)),

        load5m:
            Number(loadAverage[1].toFixed(2)),

        load15m:
            Number(loadAverage[2].toFixed(2)),
    };
}

/* =========================================================
   STORAGE INFORMATION
========================================================= */

async function getStorageInfo() {
    if (process.platform !== "darwin" &&
        process.platform !== "linux") {
        return {
            totalGB: null,
            usedGB: null,
            freeGB: null,
            usagePercent: null,
        };
    }

    const result =
        await runCommand(
            "df -k /"
        );

    if (!result.success) {
        return {
            totalGB: null,
            usedGB: null,
            freeGB: null,
            usagePercent: null,
        };
    }

    const lines =
        result.output
            .split("\n")
            .filter(Boolean);

    if (lines.length < 2) {
        return {
            totalGB: null,
            usedGB: null,
            freeGB: null,
            usagePercent: null,
        };
    }

    const parts =
        lines[lines.length - 1]
            .trim()
            .split(/\s+/);

    if (parts.length < 5) {
        return {
            totalGB: null,
            usedGB: null,
            freeGB: null,
            usagePercent: null,
        };
    }

    const totalKB =
        Number(parts[1]);

    const usedKB =
        Number(parts[2]);

    const freeKB =
        Number(parts[3]);

    const usageText =
        parts[4];

    const usagePercent =
        Number(
            usageText.replace("%", "")
        );

    return {
        totalGB: Number(
            (
                totalKB /
                1024 /
                1024
            ).toFixed(2)
        ),

        usedGB: Number(
            (
                usedKB /
                1024 /
                1024
            ).toFixed(2)
        ),

        freeGB: Number(
            (
                freeKB /
                1024 /
                1024
            ).toFixed(2)
        ),

        usagePercent:
            Number.isFinite(
                usagePercent
            )
                ? usagePercent
                : null,
    };
}

/* =========================================================
   NETWORK INFORMATION
========================================================= */

function getNetworkInfo() {
    const interfaces =
        os.networkInterfaces();

    const result = [];

    for (const [name, addresses] of Object.entries(interfaces)) {
        if (!Array.isArray(addresses)) {
            continue;
        }

        for (const address of addresses) {
            result.push({
                interface: name,
                address: address.address,
                family: address.family,
                internal: address.internal,
                mac: address.mac,
            });
        }
    }

    return result;
}

/* =========================================================
   DEVICE INFORMATION
========================================================= */

function getDeviceInfo() {
    let username = "Unknown";

    try {
        username =
            os.userInfo().username;
    } catch {
        username = "Unknown";
    }

    const memory =
        getMemoryInfo();

    const cpu =
        getCPUInfo();

    return {
        hostname:
            os.hostname(),

        platform:
            process.platform,

        operatingSystem:
            `${os.type()} ${os.release()}`,

        architecture:
            os.arch(),

        cpu:
            cpu.model,

        cpuCores:
            cpu.cores,

        cpuLoad1m:
            cpu.load1m,

        cpuLoad5m:
            cpu.load5m,

        cpuLoad15m:
            cpu.load15m,

        totalMemoryGB:
            memory.totalGB,

        freeMemoryGB:
            memory.freeGB,

        usedMemoryGB:
            memory.usedGB,

        memoryUsagePercent:
            memory.usagePercent,

        uptimeMinutes:
            Math.floor(
                os.uptime() /
                60
            ),

        username,

        online: true,
    };
}

/* =========================================================
   APPLICATION INVENTORY
========================================================= */

async function getInstalledApplications() {
    if (process.platform !== "darwin") {
        return [];
    }

    const command =
        `find /Applications /System/Applications "$HOME/Applications" -maxdepth 2 -type d -name "*.app" 2>/dev/null`;

    const result =
        await runCommand(command);

    if (!result.success) {
        console.log(
            "[Applications] Scan failed:",
            result.output
        );

        return [];
    }

    const paths =
        result.output
            .split("\n")
            .map((item) => item.trim())
            .filter(Boolean);

    const applications = [];

    for (const appPath of paths) {
        const name =
            appPath
                .split("/")
                .pop()
                .replace(/\.app$/i, "");

        const versionResult =
            await runCommand(
                `/usr/bin/mdls -name kMDItemVersion -raw "${appPath}"`
            );

        let version =
            versionResult.output;

        if (
            !version ||
            version === "(null)"
        ) {
            version = "Unknown";
        }

        applications.push({
            name,
            version,
            path: appPath,
            detectedAt:
                new Date().toISOString(),
        });
    }

    return applications;
}

/* =========================================================
   SEND APPLICATION INVENTORY
========================================================= */

async function sendApplicationInventory(device) {
    try {
        const applications =
            await getInstalledApplications();

        console.log("");
        console.log(
            "======================================="
        );
        console.log(
            "       APPLICATION INVENTORY"
        );
        console.log(
            "======================================="
        );

        console.log(
            "Device:",
            device.hostname
        );

        console.log(
            "Applications found:",
            applications.length
        );

        if (applications.length === 0) {
            console.log(
                "No applications detected."
            );

            return;
        }

        for (const application of applications) {
            console.log(
                `${application.name} | ${application.version} | ${application.path}`
            );
        }

        const payload = {
            device_id:
                device.hostname,

            hostname:
                device.hostname,

            applications,
        };

        const response =
            await fetch(
                `${SERVER_URL}/api/agent/applications`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body:
                        JSON.stringify(
                            payload
                        ),
                }
            );

        const data =
            await response.json();

        console.log(
            "Application API status:",
            response.status
        );

        console.log(
            "Application API response:",
            data.message ||
                "No server message"
        );

        console.log(
            "======================================="
        );
    } catch (error) {
        console.log("");
        console.log(
            "Application inventory error:",
            error.message
        );
    }
}

/* =========================================================
   SEND HEARTBEAT
========================================================= */

async function sendHeartbeat() {
    try {
        const device =
            getDeviceInfo();

        const security =
            await getSecurityInfo();

        const storage =
            await getStorageInfo();

        const network =
            getNetworkInfo();

        const now =
            new Date().toISOString();

        const payload = {
            hostname:
                device.hostname,

            device_id:
                device.hostname,

            name:
                device.hostname,

            platform:
                device.platform,

            operatingSystem:
                device.operatingSystem,

            operating_system:
                device.operatingSystem,

            architecture:
                device.architecture,

            cpu:
                device.cpu,

            cpuCores:
                device.cpuCores,

            cpu_cores:
                device.cpuCores,

            cpuLoad1m:
                device.cpuLoad1m,

            cpu_load_1m:
                device.cpuLoad1m,

            cpuLoad5m:
                device.cpuLoad5m,

            cpu_load_5m:
                device.cpuLoad5m,

            cpuLoad15m:
                device.cpuLoad15m,

            cpu_load_15m:
                device.cpuLoad15m,

            totalMemoryGB:
                device.totalMemoryGB,

            freeMemoryGB:
                device.freeMemoryGB,

            usedMemoryGB:
                device.usedMemoryGB,

            memoryUsagePercent:
                device.memoryUsagePercent,

            memory_usage_percent:
                device.memoryUsagePercent,

            ram_gb:
                device.totalMemoryGB,

            free_ram_gb:
                device.freeMemoryGB,

            username:
                device.username,

            employee:
                device.username,

            department:
                "Unassigned",

            online:
                true,

            uptimeMinutes:
                device.uptimeMinutes,

            uptime_minutes:
                device.uptimeMinutes,

            agentVersion:
                AGENT_VERSION,

            agent_version:
                AGENT_VERSION,

            storage,

            network,

            security,

            securityStatus:
                security.overallStatus,

            security_status:
                security.overallStatus,

            securityMessage:
                security.message,

            security_message:
                security.message,

            securityCheckedAt:
                security.checkedAt,

            security_checked_at:
                security.checkedAt,

            antivirusStatus:
                security.antivirus.status,

            antivirus_status:
                security.antivirus.status,

            antivirus:
                security.antivirus.enabled,

            antivirusProduct:
                security.antivirus.product,

            antivirus_product:
                security.antivirus.product,

            firewallStatus:
                security.firewall.status,

            firewall_status:
                security.firewall.status,

            firewall:
                security.firewall.enabled,

            backupStatus:
                security.backup.status,

            backup_status:
                security.backup.status,

            backup:
                security.backup.enabled,

            lastSeen:
                now,

            last_seen:
                now,
        };

        console.log("");
        console.log(
            "======================================="
        );
        console.log(
            "       SENTINEL DEVICE MONITOR"
        );
        console.log(
            "======================================="
        );

        console.log("");
        console.log(
            "DEVICE INFORMATION"
        );
        console.log(
            "------------------"
        );

        console.log(
            "Device:",
            device.hostname
        );

        console.log(
            "OS:",
            device.operatingSystem
        );

        console.log(
            "Architecture:",
            device.architecture
        );

        console.log(
            "CPU:",
            device.cpu
        );

        console.log(
            "CPU Cores:",
            device.cpuCores
        );

        console.log(
            "CPU Load 1m:",
            device.cpuLoad1m
        );

        console.log(
            "RAM:",
            device.totalMemoryGB,
            "GB"
        );

        console.log(
            "Used RAM:",
            device.usedMemoryGB,
            "GB"
        );

        console.log(
            "Free RAM:",
            device.freeMemoryGB,
            "GB"
        );

        console.log(
            "Memory Usage:",
            device.memoryUsagePercent,
            "%"
        );

        console.log(
            "Uptime:",
            device.uptimeMinutes,
            "minutes"
        );

        console.log(
            "Username:",
            device.username
        );

        console.log(
            "Agent Version:",
            AGENT_VERSION
        );

        console.log("");
        console.log(
            "STORAGE INFORMATION"
        );
        console.log(
            "-------------------"
        );

        console.log(
            "Storage Total:",
            storage.totalGB,
            "GB"
        );

        console.log(
            "Storage Used:",
            storage.usedGB,
            "GB"
        );

        console.log(
            "Storage Free:",
            storage.freeGB,
            "GB"
        );

        console.log(
            "Storage Usage:",
            storage.usagePercent,
            "%"
        );

        console.log("");
        console.log(
            "NETWORK INFORMATION"
        );
        console.log(
            "-------------------"
        );

        console.log(
            "Network Interfaces:",
            network.length
        );

        console.log("");
        console.log(
            "SECURITY INFORMATION"
        );
        console.log(
            "--------------------"
        );

        console.log(
            "Antivirus:",
            security.antivirus.status
        );

        console.log(
            "Antivirus Product:",
            security.antivirus.product
        );

        console.log(
            "Firewall:",
            security.firewall.status
        );

        console.log(
            "Backup:",
            security.backup.status
        );

        console.log(
            "Security Status:",
            security.overallStatus
        );

        console.log(
            "Checked:",
            security.checkedAt
        );

        console.log("");
        console.log(
            "Sending heartbeat..."
        );

        const response =
            await fetch(
                `${SERVER_URL}/api/agent/heartbeat`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body:
                        JSON.stringify(
                            payload
                        ),
                }
            );

        const data =
            await response.json();

        console.log("");
        console.log(
            "SERVER RESPONSE"
        );
        console.log(
            "----------------"
        );

        console.log(
            "HTTP Status:",
            response.status
        );

        console.log(
            "Message:",
            data.message ||
                "No server message"
        );

        console.log(
            "Status: ONLINE"
        );

        console.log(
            "Security:",
            security.overallStatus
        );

        console.log(
            "Antivirus:",
            security.antivirus.status
        );

        console.log(
            "Firewall:",
            security.firewall.status
        );

        console.log(
            "Backup:",
            security.backup.status
        );

        console.log(
            "======================================="
        );
    } catch (error) {
        console.log("");
        console.log(
            "======================================="
        );

        console.log(
            "       SENTINEL AGENT ERROR"
        );

        console.log(
            "======================================="
        );

        console.log(
            error.message
        );

        console.log("");

        console.log(
            "Make sure Sentinel API is running:"
        );

        console.log(
            SERVER_URL
        );

        console.log(
            "======================================="
        );
    }
}

/* =========================================================
   START AGENT
========================================================= */

console.log("");

console.log(
    "======================================="
);

console.log(
    "       SENTINEL AGENT STARTED"
);

console.log(
    "======================================="
);

console.log(
    "Agent Version:",
    AGENT_VERSION
);

console.log(
    "Heartbeat:",
    HEARTBEAT_INTERVAL / 1000,
    "seconds"
);

console.log(
    "Application Scan:",
    APPLICATION_SCAN_INTERVAL / 1000,
    "seconds"
);

console.log(
    "Server:",
    SERVER_URL
);

console.log(
    "Operating System:",
    process.platform
);

console.log(
    "======================================="
);

sendHeartbeat();

setTimeout(
    async function runInitialApplicationScan() {
        const device =
            getDeviceInfo();

        await sendApplicationInventory(
            device
        );
    },
    5000
);

setInterval(
    sendHeartbeat,
    HEARTBEAT_INTERVAL
);

setInterval(
    async function runApplicationScan() {
        const device =
            getDeviceInfo();

        await sendApplicationInventory(
            device
        );
    },
    APPLICATION_SCAN_INTERVAL
);
