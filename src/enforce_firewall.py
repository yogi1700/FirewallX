import subprocess


def rule_exists(rule_name):

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        f"name={rule_name}"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    # If rule name appears in output, rule exists
    return rule_name in result.stdout


def enforce_ip_block(ip):

    rule_name = f"FirewallX_{ip}"

    # Prevent duplicate rule in Windows Firewall
    if rule_exists(rule_name):
        print(f"[SKIP] Rule already exists for {ip}")
        return

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip}"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    print(result.stdout)
    print(result.stderr)

    print(f"[ENFORCED 🔒] Block rule added for {ip}")

def remove_ip_block(ip):

    rule_name = f"FirewallX_{ip}"

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    print(result.stdout)
    print(result.stderr)

    print(f"[RELEASE 🔓] Block rule removed for {ip}")