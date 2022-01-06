import configparser
import dataclasses
import json
import os.path
import subprocess

import click
import jq
import requests
from click import secho
from yaspin import kbi_safe_yaspin
from yaspin.spinners import Spinners


CONFIG_FILE = os.path.expanduser("~/.aws/aws_robot")


@dataclasses.dataclass
class SshConfig:
    profile_name: str
    security_group_id: str
    ssh_port: int
    narrative: str


@kbi_safe_yaspin(Spinners.line, text="determining public ip", color="yellow")
def get_public_ip() -> str:
    try:
        return str(requests.get("https://checkip.amazonaws.com").text).strip()
    except requests.RequestException:
        raise RuntimeError("unable to determine public ip")


def load_profile(profile: str) -> SshConfig:
    conf = configparser.ConfigParser()
    conf.read(CONFIG_FILE)
    if profile not in conf:
        raise RuntimeError(f"profile '{profile}' is not configured")
    return SshConfig(
        profile,
        conf[profile]["security_group"],
        int(conf[profile]["ssh_port"]),
        conf[profile]["narrative"],
    )


@kbi_safe_yaspin(Spinners.line, text="revoking access for previous IP", color="red")
def revoke_access(conf: SshConfig, ip_range):
    req = f'IpProtocol=tcp,FromPort={conf.ssh_port},ToPort={conf.ssh_port},IpRanges=[{{CidrIp="{ip_range}",Description="{conf.narrative}"}}]'
    result = subprocess.run(
        [
            "aws",
            "--profile",
            conf.profile_name,
            "ec2",
            "revoke-security-group-ingress",
            "--group-id",
            conf.security_group_id,
            "--ip-permissions",
            req,
        ],
        stdout=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("unable to update AWS settings")


@kbi_safe_yaspin(Spinners.line, text="granting access to new IP", color="green")
def grant_access(conf: SshConfig, ip_range):
    req = f'IpProtocol=tcp,FromPort={conf.ssh_port},ToPort={conf.ssh_port},IpRanges=[{{CidrIp="{ip_range}",Description="{conf.narrative}"}}]'
    result = subprocess.run(
        [
            "aws",
            "--profile",
            conf.profile_name,
            "ec2",
            "authorize-security-group-ingress",
            "--group-id",
            conf.security_group_id,
            "--ip-permissions",
            req,
        ],
        stdout=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("unable to update AWS settings")


@kbi_safe_yaspin(Spinners.line, text="loading AWS settings", color="blue")
def configure_ip_rules(conf: SshConfig, ip_address):
    result = subprocess.run(
        [
            "aws",
            "--profile",
            conf.profile_name,
            "ec2",
            "describe-security-groups",
            "--group-ids",
            conf.security_group_id,
        ],
        stdout=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("unable to fetch current AWS settings")
    approved_ips = (
        jq.compile(
            f".SecurityGroups[0].IpPermissions[]|select(.FromPort == {conf.ssh_port})|.IpRanges[]|select(.Description "
            f'== "{conf.narrative}")|.CidrIp '
        )
        .input(json.loads(result.stdout))
        .all()
    )
    already_approved = f"{ip_address}/32" in approved_ips
    if already_approved and len(approved_ips) == 1:
        return

    for i in approved_ips:
        if i == f"{ip_address}/32":
            continue
        revoke_access(conf, i)

    if not already_approved:
        grant_access(conf, f"{ip_address}/32")


@click.group()
def robot():
    """
    Manage AWS SSH IP access through a Security Group
    """
    pass


@robot.command()
@click.option(
    "-p",
    "--profile",
    "profile",
    help="The AWS profile that will be used",
    default="default",
)
def grant(profile: str):
    """
    Grant SSH access to your current public IP
    """
    try:
        profile_conf = load_profile(profile)
        my_ip = get_public_ip()
        configure_ip_rules(profile_conf, my_ip)
        secho("ssh access is granted", fg="green")
    except RuntimeError as e:
        secho(str(e), err=True, fg="red")


@robot.command()
@click.option(
    "-p",
    "--profile",
    "profile",
    help="The AWS profile that will be used",
    default="default",
)
def config(profile: str):
    """
    Create/Update a robot profile
    """
    conf = configparser.ConfigParser()
    conf.read(CONFIG_FILE)

    ssh_port = click.prompt(
        "What's the SSH port?",
        default=22 if not conf[profile] else conf[profile]["ssh_port"],
        type=int,
    )
    security_group = click.prompt(
        "What security group should be modified?",
        default=conf[profile]["security_group"] if conf[profile] else None,
        type=str,
    )
    description = click.prompt(
        "What identifier should be used for this rule?",
        default=conf[profile]["narrative"] if conf[profile] else None,
        type=str,
    )

    conf[profile] = {
        "security_group": security_group,
        "ssh_port": ssh_port,
        "narrative": description,
    }
    with open(CONFIG_FILE, "w") as f:
        conf.write(f)
    secho("configuration updated")
