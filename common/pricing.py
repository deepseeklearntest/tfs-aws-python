"""
Region-aware AWS pricing helpers.

All base prices are us-east-1 list pricing. Each lookup multiplies by a regional
factor approximated from the public AWS pricing pages (±5% for most services).

For audit-grade pricing, replace these with AWS Pricing API lookups; for
prioritisation purposes the multipliers are accurate enough.
"""
from __future__ import annotations

# Approximate price multipliers vs us-east-1 list pricing.
REGION_MULTIPLIER: dict[str, float] = {
    'us-east-1': 1.00,
    'us-east-2': 1.00,
    'us-west-1': 1.05,
    'us-west-2': 1.00,
    'ca-central-1': 1.10,
    'eu-west-1': 1.10,
    'eu-west-2': 1.12,
    'eu-west-3': 1.12,
    'eu-central-1': 1.15,
    'eu-north-1': 1.05,
    'eu-south-1': 1.10,
    'ap-northeast-1': 1.20,
    'ap-northeast-2': 1.13,
    'ap-northeast-3': 1.20,
    'ap-southeast-1': 1.10,
    'ap-southeast-2': 1.10,
    'ap-southeast-3': 1.10,
    'ap-south-1': 0.95,
    'sa-east-1': 1.45,
    'me-south-1': 1.35,
    'me-central-1': 1.30,
    'af-south-1': 1.30,
}


def region_multiplier(region: str) -> float:
    return REGION_MULTIPLIER.get(region, 1.0)


# ---------------------------------------------------------------------------
# EBS volumes & snapshots
# ---------------------------------------------------------------------------
EBS_BASE_PER_GB = {
    'gp2': 0.10,
    'gp3': 0.08,
    'io1': 0.125,
    'io2': 0.125,
    'st1': 0.045,
    'sc1': 0.015,
    'standard': 0.05,
}
SNAPSHOT_BASE_PER_GB = 0.05


def ebs_price_per_gb(region: str, volume_type: str) -> float:
    return EBS_BASE_PER_GB.get(volume_type, EBS_BASE_PER_GB['gp2']) * region_multiplier(region)


def gp2_to_gp3_savings_per_gb(region: str) -> float:
    return (EBS_BASE_PER_GB['gp2'] - EBS_BASE_PER_GB['gp3']) * region_multiplier(region)


def snapshot_price_per_gb(region: str) -> float:
    return SNAPSHOT_BASE_PER_GB * region_multiplier(region)


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
def eip_monthly_cost(region: str) -> float:
    """Idle EIP charge: $0.005/hour * 730 hours."""
    return 3.65 * region_multiplier(region)


def nat_gateway_hourly_price(region: str) -> float:
    """NAT Gateway existence charge: $0.045/hour regardless of traffic."""
    return 0.045 * region_multiplier(region)


def nat_gateway_data_price_per_gb(region: str) -> float:
    """NAT Gateway data processing charge: $0.045/GB."""
    return 0.045 * region_multiplier(region)


# Minimum monthly cost (no traffic / LCUs) for each LB type
_LB_FLOOR = {
    'classic': 18.00,
    'application': 5.84,
    'network': 4.38,
    'gateway': 0.0,
}


def lb_monthly_floor(region: str, lb_type: str) -> float:
    return _LB_FLOOR.get(lb_type, 0.0) * region_multiplier(region)


# ---------------------------------------------------------------------------
# Storage / observability
# ---------------------------------------------------------------------------
def cloudwatch_logs_storage_per_gb(region: str) -> float:
    return 0.03 * region_multiplier(region)


def s3_standard_per_gb(region: str) -> float:
    return 0.023 * region_multiplier(region)


# ---------------------------------------------------------------------------
# Compute (very rough — for directional savings only)
# ---------------------------------------------------------------------------
EC2_HOURLY_BY_FAMILY: dict[str, float] = {
    't2': 0.023, 't3': 0.026, 't3a': 0.022, 't4g': 0.021,
    'm4': 0.100, 'm5': 0.096, 'm5a': 0.086, 'm5n': 0.119,
    'm6i': 0.096, 'm6a': 0.086, 'm6g': 0.077, 'm7i': 0.101, 'm7g': 0.082,
    'c4': 0.100, 'c5': 0.085, 'c5a': 0.077, 'c5n': 0.108,
    'c6i': 0.085, 'c6a': 0.077, 'c6g': 0.068, 'c7i': 0.0892, 'c7g': 0.0725,
    'r4': 0.133, 'r5': 0.126, 'r5a': 0.113, 'r5n': 0.149,
    'r6i': 0.126, 'r6a': 0.1134, 'r6g': 0.1008, 'r7i': 0.1323, 'r7g': 0.1075,
    'i3': 0.156, 'i4i': 0.1715,
}
EC2_HOURLY_DEFAULT = 0.05


def ec2_hourly_estimate(region: str, instance_type: str) -> float:
    family = instance_type.split('.')[0]
    base = EC2_HOURLY_BY_FAMILY.get(family, EC2_HOURLY_DEFAULT)
    return base * region_multiplier(region)


# Approximate RDS on-demand price floor per vCPU-hour (db.t3 family)
RDS_PRICE_PER_VCPU_HOUR = 0.034
_RDS_VCPU_BY_SIZE = {
    'nano': 1, 'micro': 1, 'small': 1, 'medium': 2, 'large': 2,
    'xlarge': 4, '2xlarge': 8, '4xlarge': 16, '8xlarge': 32,
    '12xlarge': 48, '16xlarge': 64, '24xlarge': 96,
}


def rds_monthly_estimate(region: str, db_class: str) -> float:
    """Rough monthly cost for an RDS db.* class. Directional only."""
    size = db_class.split('.')[-1] if '.' in db_class else 'medium'
    vcpus = _RDS_VCPU_BY_SIZE.get(size, 2)
    return vcpus * RDS_PRICE_PER_VCPU_HOUR * 730 * region_multiplier(region)
