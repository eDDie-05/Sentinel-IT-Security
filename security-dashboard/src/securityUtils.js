export function isDeviceSecure(
    device,
    securityPolicy
) {

    const antivirusRequired =
        securityPolicy?.antivirus_required === true ||
        securityPolicy?.antivirusRequired === true;

    const firewallRequired =
        securityPolicy?.firewall_required === true ||
        securityPolicy?.firewallRequired === true;

    const backupRequired =
        securityPolicy?.backup_required === true ||
        securityPolicy?.backupRequired === true;


    const antivirusOK =
        !antivirusRequired ||
        device.antivirus === true;

    const firewallOK =
        !firewallRequired ||
        device.firewall === true;

    const backupOK =
        !backupRequired ||
        device.backup === true;


    return (
        antivirusOK &&
        firewallOK &&
        backupOK
    );
}


export function getDeviceSecurityProblems(
    device,
    securityPolicy
) {

    const problems = [];


    const antivirusRequired =
        securityPolicy?.antivirus_required === true ||
        securityPolicy?.antivirusRequired === true;

    const firewallRequired =
        securityPolicy?.firewall_required === true ||
        securityPolicy?.firewallRequired === true;

    const backupRequired =
        securityPolicy?.backup_required === true ||
        securityPolicy?.backupRequired === true;


    if (
        antivirusRequired &&
        device.antivirus !== true
    ) {

        problems.push({
            type: "Antivirus",
            message:
                "Antivirus protection is disabled."
        });
    }


    if (
        firewallRequired &&
        device.firewall !== true
    ) {

        problems.push({
            type: "Firewall",
            message:
                "Firewall protection is disabled."
        });
    }


    if (
        backupRequired &&
        device.backup !== true
    ) {

        problems.push({
            type: "Backup",
            message:
                "Backup protection is disabled."
        });
    }


    return problems;
}