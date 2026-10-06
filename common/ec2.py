"""
Shared EC2 lookup helpers.

Imports only botocore.exceptions.ClientError (never botocore.config), so it is
safe to import from any script regardless of truststore/SSL injection ordering
(see CLAUDE.md's "botocore.config must be imported after common.session" note
— botocore.exceptions does not transitively hit botocore.httpsession the way
botocore.config does, matching the existing import order in scripts like
wave5_performance/40_detect_idle_provisioned_iops.py).
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from common import session

log = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 200


def describe_instances_by_id(
    ec2, instance_ids: list[str], batch_size: int = DEFAULT_BATCH_SIZE
) -> dict[str, dict]:
    """
    Return {instance_id: instance_dict} for the given instance IDs.

    Uses an instance-id Filter (not InstanceIds=) so a terminated/missing
    instance is silently omitted from the response instead of raising
    InvalidInstanceID.NotFound. Skippable ClientErrors (see
    common.session.SKIP_CODES) are logged and that chunk is skipped;
    non-skippable ClientErrors propagate, matching this codebase's
    "skip known codes, raise everything else" convention (see
    common.session.is_skippable and its callers).
    """
    result: dict[str, dict] = {}
    if not instance_ids:
        return result

    for chunk in session.chunked(instance_ids, batch_size):
        try:
            paginator = ec2.get_paginator('describe_instances')
            for page in paginator.paginate(
                Filters=[{'Name': 'instance-id', 'Values': chunk}]
            ):
                for reservation in page.get('Reservations', []):
                    for inst in reservation.get('Instances', []):
                        result[inst['InstanceId']] = inst
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning(
                    "describe_instances: skipped — %s",
                    exc.response['Error']['Code'],
                )
                continue
            raise

    return result
