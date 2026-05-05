from .ssh import check_sshdconfig_permissions, sshdconfig_permissions_remediation

CHECKS = {
    "ssh": {
        "check": check_sshdconfig_permissions,
        "description": "Checks the sshd_config file for potential misconfigurations."
    }
}

REMEDIATIONS = {
    "ssh": {
        "remediate": sshdconfig_permissions_remediation,
        "description": "Remediates permissions for sshd_config file to ensure they are secure"
    }
}