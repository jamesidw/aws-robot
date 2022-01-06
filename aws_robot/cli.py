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


def get_configuration(profile: str) -> SshConfig:
    config = configparser.ConfigParser()
    config.read(os.path.expanduser("~/.aws/aws_robot"))
    if profile not in config:
        raise RuntimeError("profile not configured")
    return SshConfig(
        profile,
        config[profile]["security_group"],
        int(config[profile]["ssh_port"]),
        config[profile]["narrative"],
    )


@kbi_safe_yaspin(Spinners.line, text="revoking access for previous IP", color="red")
def revoke_access(conf: SshConfig, ip_range):
    req = f'IpProtocol=tcp,FromPort={conf.ssh_port},ToPort={conf.ssh_port},IpRanges=[{{CidrIp={ip_range},Description="{conf.narrative}"}}]'
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


@click.command()
@click.argument("profile")
def grant_ssh_access(profile: str):
    try:
        my_ip = get_public_ip()
        profile_conf = get_configuration(profile)
        configure_ip_rules(profile_conf, my_ip)
        secho("ssh access is granted", fg="green")
    except RuntimeError as e:
        secho(str(e), err=True, fg="red")
