#!/usr/bin/env python3
"""Task 30 — Security Groups with 0.0.0.0/0 on Sensitive Ports

Finds EC2 security group inbound rules that expose sensitive ports to the
public internet (0.0.0.0/0 or ::/0). One finding is written per offending
rule, so a single security group may produce multiple findings.

Sensitive ports checked: 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (Postgres),
1433 (MSSQL), 6379 (Redis), 27017/27018 (MongoDB), 9200/9300 (Elasticsearch),
2181 (ZooKeeper).

ICMP rules are reported separately: AWS repurposes FromPort/ToPort as ICMP
type/code for these rules, not L4 ports, so they are never matched against
the sensitive-port list above. Echo-only rules (type=8 request or type=0
reply — i.e. ping) are reported as finding='icmp-echo-open-to-internet'
(Low severity); anything broader (type=all or any other single type, which
also carries ICMPv6 control traffic such as Neighbor Discovery) is reported
as finding='icmp-open-to-internet' (Medium severity).

Run: python 30_detect_open_security_groups.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '30_detect_open_security_groups'
EXTRA_FIELDS = [
    'sg_name', 'vpc_id', 'protocol', 'port_range', 'cidr', 'description',
    'sg_rule_id', 'associated_resources',
]

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 9300, 2181, 27018}

# For ICMP/ICMPv6 rules, FromPort/ToPort hold ICMP type/code, not L4 ports —
# these must never be run through _overlaps_sensitive's port-range logic.
ICMP_PROTOCOLS = {'icmp', 'icmpv6'}

log = logging.getLogger(SCRIPT_NAME)


def _overlaps_sensitive(protocol: str, from_port, to_port) -> bool:
    """Return True if this rule touches any sensitive port.

    Callers must route ICMP/ICMPv6 rules to their own finding before
    reaching this function — FromPort/ToPort mean ICMP type/code there,
    not ports, and would otherwise be misread as an unbounded port range.
    """
    if protocol == '-1':
        return True
    # describe_security_group_rules uses -1 for unset ports on all-traffic rules
    if from_port is None or from_port == -1:
        return True
    tp = to_port if (to_port is not None and to_port != -1) else 65535
    return any(from_port <= port <= tp for port in SENSITIVE_PORTS)


def _format_icmp_type_code(from_port, to_port) -> tuple[str, str]:
    """Render ICMP type/code, where -1 or unset means 'all'."""
    type_str = 'all' if from_port is None or from_port == -1 else str(from_port)
    code_str = 'all' if to_port is None or to_port == -1 else str(to_port)
    return type_str, code_str


def _format_port_range(from_port, to_port, protocol) -> str:
    if protocol == '-1':
        return 'all'
    if from_port is None or from_port == -1:
        return 'all'
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def _get_associated_resources(ec2, sg_id: str, cache: dict) -> str:
    """Return a compact string of resources attached to sg_id via ENIs."""
    if sg_id in cache:
        return cache[sg_id]

    try:
        paginator = ec2.get_paginator('describe_network_interfaces')
        enis = []
        for page in paginator.paginate(Filters=[{'Name': 'group-id', 'Values': [sg_id]}]):
            enis.extend(page.get('NetworkInterfaces', []))
    except ClientError as exc:
        log.warning("describe_network_interfaces failed for %s: %s", sg_id, exc)
        cache[sg_id] = ''
        return ''

    if not enis:
        cache[sg_id] = 'none'
        return 'none'

    parts = []
    for eni in enis:
        itype = eni.get('InterfaceType', 'unknown')
        instance_id = eni.get('Attachment', {}).get('InstanceId')
        if instance_id:
            parts.append(f"ec2:{instance_id}")
        else:
            parts.append(f"{itype}:{eni['NetworkInterfaceId']}")

    if len(parts) > 8:
        result = ','.join(parts[:8]) + f',+{len(parts) - 8}more'
    else:
        result = ','.join(parts)

    cache[sg_id] = result
    return result


def scan(sess, account_id: str, region: str, writer) -> None:
    ec2 = sess.client('ec2', region_name=region)
    try:
        paginator = ec2.get_paginator('describe_security_groups')
        security_groups = []
        for page in paginator.paginate():
            security_groups.extend(page.get('SecurityGroups', []))
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: skipped — %s", account_id, region, exc.response['Error']['Code'])
            return
        raise

    # Cache ENI lookups per SG within this account/region scan call
    eni_cache: dict[str, str] = {}

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', '')
        vpc_id = sg.get('VpcId', '')
        sg_description = sg.get('Description', '')
        tags = sg.get('Tags')

        # describe_security_group_rules returns flat rules (one CIDR per entry)
        # with stable SecurityGroupRuleId — preferred over IpPermissions for this reason.
        try:
            rules_paginator = ec2.get_paginator('describe_security_group_rules')
            sg_rules = []
            for page in rules_paginator.paginate(
                Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
            ):
                sg_rules.extend(page.get('SecurityGroupRules', []))
        except ClientError as exc:
            if session.is_skippable(exc):
                continue
            raise

        for rule in sg_rules:
            if rule.get('IsEgress', True):
                continue

            protocol = rule.get('IpProtocol', '-1')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            cidr_v4 = rule.get('CidrIpv4', '')
            cidr_v6 = rule.get('CidrIpv6', '')

            if cidr_v4 == '0.0.0.0/0':
                cidr = '0.0.0.0/0'
            elif cidr_v6 == '::/0':
                cidr = '::/0'
            else:
                continue

            sg_rule_id = rule.get('SecurityGroupRuleId', '')

            if protocol in ICMP_PROTOCOLS:
                icmp_type, icmp_code = _format_icmp_type_code(from_port, to_port)
                icmp_finding = (
                    'icmp-echo-open-to-internet' if icmp_type in ('0', '8')
                    else 'icmp-open-to-internet'
                )
                associated = _get_associated_resources(ec2, sg_id, eni_cache)
                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=sg_id,
                    resource_type='Security Group',
                    finding=icmp_finding,
                    detail=(
                        f"SG={sg_name} VPC={vpc_id} Protocol={protocol} "
                        f"Type={icmp_type} Code={icmp_code} CIDR={cidr}"
                    ),
                    estimated_monthly_savings_usd=0,
                    tags=tags,
                    sg_name=sg_name,
                    vpc_id=vpc_id,
                    protocol=protocol,
                    port_range=f"type={icmp_type}/code={icmp_code}",
                    cidr=cidr,
                    description=sg_description,
                    sg_rule_id=sg_rule_id,
                    associated_resources=associated,
                )
                continue

            if not _overlaps_sensitive(protocol, from_port, to_port):
                continue

            port_range_str = _format_port_range(from_port, to_port, protocol)
            proto_display = 'all' if protocol == '-1' else protocol
            associated = _get_associated_resources(ec2, sg_id, eni_cache)

            writer.write(
                account_id=account_id,
                region=region,
                resource_id=sg_id,
                resource_type='Security Group',
                finding='open-to-internet',
                detail=(
                    f"SG={sg_name} VPC={vpc_id} "
                    f"Protocol={proto_display} Ports={port_range_str} CIDR={cidr}"
                ),
                estimated_monthly_savings_usd=0,
                tags=tags,
                sg_name=sg_name,
                vpc_id=vpc_id,
                protocol=proto_display,
                port_range=port_range_str,
                cidr=cidr,
                description=sg_description,
                sg_rule_id=sg_rule_id,
                associated_resources=associated,
            )


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
