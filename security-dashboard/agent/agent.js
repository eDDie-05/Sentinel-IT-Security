const os = require("os");
const { exec } = require("child_process");

const SERVER_URL = "http://localhost:5000";

// ========================================
// RUN TERMINAL COMMAND
// ========================================
function runCommand(command) {
  return new Promise((resolve) => {
    exec(command, (error, stdout, stderr) => {
      resolve({
        success: !error,
        output: (stdout || stderr || error?.message || "").trim(),
      });
    });
  });
}

// ========================================
// CHECK FIREWALL
// ========================================
async function checkFirewall() {
  if (process.platform !== "darwin") {
    return {
      status: "UNKNOWN",
      enabled: null,
      message: "Firewall check currently supported on macOS",
    };
  }

  const result = await runCommand(
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
  );

  const output = result.output.toLowerCase();

  if (
    output.includes("enabled") ||
    output.includes("state = 1")
  ) {
    return {
      status: "ENABLED",
      enabled: true,
      message: "macOS firewall is enabled",
    };
  }

  if (
    output.includes("disabled") ||
    output.includes("state = 0")
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
    message: "Unable to determine firewall status",
  };
}

// ========================================
// CHECK TIME MACHINE BACKUP
// ========================================
async function checkBackup() {
  if (process.platform !== "darwin") {
    return {
      status: "UNKNOWN",
      enabled: null,
      message: "Backup check currently supported on macOS",
    };
  }

  const destination = await runCommand(
    "/usr/bin/tmutil destinationinfo"
  );

  const destinationOutput = (
    destination.output || ""
  ).toLowerCase();

  // No Time Machine destination
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

  // A destination is configured
  if (
    destination.success &&
    destination.output.trim().length > 0
  ) {
    return {
      status: "ENABLED",
      enabled: true,
      message: "Time Machine backup destination configured",
    };
  }

  // Check whether backup is currently running
  const backupStatus = await runCommand(
    "/usr/bin/tmutil status"
  );

  const backupOutput = (
    backupStatus.output || ""
  ).toLowerCase();

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
    message: "Unable to determine Time Machine backup status",
  };
}

// ========================================
// CHECK ANTIVIRUS / ENDPOINT SECURITY
// ========================================
async function checkAntivirus() {
  if (process.platform !== "darwin") {
    return {
      status: "UNKNOWN",
      enabled: null,
      product: "Unknown",
      message: "Antivirus check currently supported on macOS",
    };
  }

  // ----------------------------------------
  // Microsoft Defender for Endpoint
  // ----------------------------------------
  const defender = await runCommand(
    "pgrep -ifl 'mdatp|Microsoft Defender'"
  );

  const defenderOutput = (
    defender.output || ""
  ).toLowerCase();

  if (
    defender.success &&
    (
      defenderOutput.includes("mdatp") ||
      defenderOutput.includes("microsoft defender")
    )
  ) {
    return {
      status: "ENABLED",
      enabled: true,
      product: "Microsoft Defender for Endpoint",
      message: "Microsoft Defender process detected",
    };
  }

  // ----------------------------------------
  // CrowdStrike
  // ----------------------------------------
  const crowdstrike = await runCommand(
    "pgrep -ifl 'falcon|crowdstrike'"
  );

  const crowdstrikeOutput = (
    crowdstrike.output || ""
  ).toLowerCase();

  if (
    crowdstrike.success &&
    (
      crowdstrikeOutput.includes("falcon") ||
      crowdstrikeOutput.includes("crowdstrike")
    )
  ) {
    return {
      status: "ENABLED",
      enabled: true,
      product: "CrowdStrike",
      message: "CrowdStrike process detected",
    };
  }

  // ----------------------------------------
  // Sophos
  // ----------------------------------------
  const sophos = await runCommand(
    "pgrep -ifl 'sophos'"
  );

  const sophosOutput = (
    sophos.output || ""
  ).toLowerCase();

  if (
    sophos.success &&
    sophosOutput.includes("sophos")
  ) {
    return {
      status: "ENABLED",
      enabled: true,
      product: "Sophos",
      message: "Sophos process detected",
    };
  }

  // ----------------------------------------
  // No approved antivirus detected
  // ----------------------------------------
  return {
    status: "UNKNOWN",
    enabled: null,
    product: "None detected",
    message:
      "No approved antivirus integration detected",
  };
}

// ========================================
// GET SECURITY INFORMATION
// ========================================
async function getSecurityInfo() {
  const firewall = await checkFirewall();
  const backup = await checkBackup();
  const antivirus = await checkAntivirus();

  let overallStatus = "UNKNOWN";

  // Any required security control disabled
  // means the device is at risk.
  if (
    firewall.status === "DISABLED" ||
    backup.status === "DISABLED" ||
    antivirus.status === "DISABLED"
  ) {
    overallStatus = "AT RISK";
  }

  // All three controls confirmed enabled
  else if (
    firewall.status === "ENABLED" &&
    backup.status === "ENABLED" &&
    antivirus.status === "ENABLED"
  ) {
    overallStatus = "SECURE";
  }

  // At least one control cannot be determined
  else {
    overallStatus = "UNKNOWN";
  }

  return {
    antivirus,
    firewall,
    backup,
    overallStatus,
  };
}

// ========================================
// GET DEVICE INFORMATION
// ========================================
async function getDeviceInfo() {
  const cpus = os.cpus();

  const totalMemoryGB = (
    os.totalmem() /
    1024 /
    1024 /
    1024
  ).toFixed(2);

  const freeMemoryGB = (
    os.freemem() /
    1024 /
    1024 /
    1024
  ).toFixed(2);

  const uptimeMinutes = Math.floor(
    os.uptime() / 60
  );

  return {
    hostname: os.hostname(),

    platform: process.platform,

    operatingSystem:
      `${os.type()} ${os.release()}`,

    architecture: os.arch(),

    cpu:
      cpus.length > 0
        ? cpus[0].model
        : "Unknown",

    cpuCores: cpus.length,

    totalMemoryGB,

    freeMemoryGB,

    uptimeMinutes,

    username: os.userInfo().username,

    online: true,
  };
}

// ========================================
// SEND HEARTBEAT
// ========================================
async function sendHeartbeat() {
  try {
    const device = await getDeviceInfo();

    const security = await getSecurityInfo();

    const payload = {
      ...device,
      security,
    };

    console.log("");
    console.log("=======================================");
    console.log("SENTINEL DEVICE MONITOR");
    console.log("=======================================");

    console.log("");
    console.log("DEVICE INFORMATION");
    console.log("------------------");

    console.log(
      "Device:",
      device.hostname
    );

    console.log(
      "OS:",
      device.operatingSystem
    );

    console.log(
      "CPU:",
      device.cpu
    );

    console.log(
      "RAM:",
      device.totalMemoryGB,
      "GB"
    );

    console.log(
      "Username:",
      device.username
    );

    console.log("");
    console.log("SECURITY INFORMATION");
    console.log("--------------------");

    console.log(
      "Antivirus:",
      security.antivirus.status
    );

    console.log(
      "Antivirus Product:",
      security.antivirus.product ||
        "Unknown"
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

    console.log("");
    console.log("Sending heartbeat...");

    const response = await fetch(
      `${SERVER_URL}/api/agent/heartbeat`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify(payload),
      }
    );

    const data = await response.json();

    console.log("");
    console.log("SERVER RESPONSE");
    console.log("----------------");

    if (response.ok) {
      console.log(
        "Message:",
        data.message
      );

      console.log(
        "Device:",
        data.device?.hostname ||
          device.hostname
      );

      console.log(
        "Status:",
        data.device?.online
          ? "ONLINE"
          : "OFFLINE"
      );

      console.log(
        "Security:",
        data.device?.security_status ||
          security.overallStatus
      );

      console.log(
        "Antivirus:",
        data.device?.antivirus_status ||
          security.antivirus.status
      );

      console.log(
        "Firewall:",
        data.device?.firewall_status ||
          security.firewall.status
      );

      console.log(
        "Backup:",
        data.device?.backup_status ||
          security.backup.status
      );
    } else {
      console.log(
        "Server error:",
        data
      );
    }

    console.log("=======================================");

  } catch (error) {
    console.log("");
    console.log("=======================================");
    console.log("SENTINEL AGENT ERROR");
    console.log("=======================================");

    console.log(
      error.message
    );

    console.log("");

    console.log(
      "Make sure the Sentinel server is running on port 5000."
    );

    console.log("=======================================");
  }
}

// ========================================
// START SENTINEL AGENT
// ========================================

console.log("");
console.log("=======================================");
console.log("SENTINEL AGENT STARTED");
console.log("=======================================");

sendHeartbeat();

// Send heartbeat every 30 seconds
setInterval(() => {
  sendHeartbeat();
}, 30000);