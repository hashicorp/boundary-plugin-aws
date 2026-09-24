# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

# Cross-account Dynamic Host Catalog test infrastructure.
#
# This file provisions the IAM resources needed to test two-hop AssumeRole
# across two separate AWS accounts:
#
#   Account A (principal account) — the default provider
#     * cross_account_principal: the plugin assumes this role first.
#       It has sts:AssumeRole permission on the target role in Account B.
#
#   Account B (target account) — the "target" provider alias
#     * cross_account_target: holds ec2:DescribeInstances; its trust policy
#       allows the Account A principal role to assume it. (happy path)
#     * cross_account_target_no_ec2_permission: same trust policy but no
#       ec2:DescribeInstances. (error case)
#     * cross_account_target_no_trust: exists in Account B but its trust
#       policy does not allow the Account A principal. (error case)
#
# Prerequisites:
#   TARGET_AWS_ACCESS_KEY_ID, TARGET_AWS_SECRET_ACCESS_KEY, and (for temporary
#   credentials) TARGET_AWS_SESSION_TOKEN must be set to credentials that have
#   sufficient IAM permissions in Account B. The test runner skips this
#   section when the access key ID or secret access key are absent.

# ---------------------------------------------------------------------------
# Provider for Account B (target account)
# ---------------------------------------------------------------------------

provider "aws" {
  alias      = "target"
  region     = var.target_region
  access_key = var.target_access_key_id
  secret_key = var.target_secret_access_key
  token      = var.target_session_token
}

data "aws_caller_identity" "target" {
  provider = aws.target
}

# ---------------------------------------------------------------------------
# Variables for Account B credentials and region
# ---------------------------------------------------------------------------

variable "target_access_key_id" {
  description = "AWS access key ID for the target account (Account B)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "target_secret_access_key" {
  description = "AWS secret access key for the target account (Account B)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "target_session_token" {
  description = "AWS session token for the target account (Account B). Required when using temporary (STS) credentials."
  type        = string
  sensitive   = true
  default     = ""
}

variable "target_region" {
  description = "AWS region for the target account (Account B). Defaults to the same region as Account A."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Account A: cross_account_principal role
# ---------------------------------------------------------------------------

resource "random_id" "cross_account_principal_name" {
  prefix      = "BoundaryPluginCAPrincipal"
  byte_length = 4
}

resource "aws_iam_role" "cross_account_principal" {
  name = random_id.cross_account_principal_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

# Allow the principal role to assume the happy-path and no-EC2-permission
# target roles in Account B.
resource "aws_iam_policy" "cross_account_principal_assume_targets" {
  name = "${random_id.cross_account_principal_name.dec}-assume-targets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect   = "Allow"
        Resource = [
          aws_iam_role.cross_account_target.arn,
          aws_iam_role.cross_account_target_no_ec2_permission.arn,
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_account_principal_assume_targets" {
  role       = aws_iam_role.cross_account_principal.name
  policy_arn = aws_iam_policy.cross_account_principal_assume_targets.arn
}

output "cross_account_principal_arn" {
  value = aws_iam_role.cross_account_principal.arn
}

# Error case: caller cannot assume the principal role (first hop denied).
# Reuses assume_role_no_trust from iam_assume_role.tf — its Deny trust policy
# also blocks the test runner from assuming it as a principal.
output "cross_account_principal_no_trust_arn" {
  value = aws_iam_role.assume_role_no_trust.arn
}

# ---------------------------------------------------------------------------
# Account B: happy-path target role
# ---------------------------------------------------------------------------

resource "random_id" "cross_account_target_name" {
  prefix      = "BoundaryPluginCATarget"
  byte_length = 4
}

resource "aws_iam_role" "cross_account_target" {
  provider = aws.target
  name     = random_id.cross_account_target_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.cross_account_principal.arn }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_policy" "cross_account_target_ec2_describeinstances" {
  provider = aws.target
  name     = "${random_id.cross_account_target_name.dec}-ec2"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["ec2:DescribeInstances"]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_account_target_ec2_describeinstances" {
  provider   = aws.target
  role       = aws_iam_role.cross_account_target.name
  policy_arn = aws_iam_policy.cross_account_target_ec2_describeinstances.arn
}

output "cross_account_target_arn" {
  value = aws_iam_role.cross_account_target.arn
}

# ---------------------------------------------------------------------------
# Account B: error case — both hops succeed but target has no ec2:DescribeInstances
# ---------------------------------------------------------------------------

resource "random_id" "cross_account_target_no_ec2_permission_name" {
  prefix      = "BoundaryPluginCATargetNoEC2"
  byte_length = 4
}

resource "aws_iam_role" "cross_account_target_no_ec2_permission" {
  provider = aws.target
  name     = random_id.cross_account_target_no_ec2_permission_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.cross_account_principal.arn }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

output "cross_account_target_no_ec2_permission_arn" {
  value = aws_iam_role.cross_account_target_no_ec2_permission.arn
}

# ---------------------------------------------------------------------------
# Account B: error case — principal cannot assume this target (second hop denied)
# ---------------------------------------------------------------------------

resource "random_id" "cross_account_target_no_trust_name" {
  prefix      = "BoundaryPluginCATargetNoTrust"
  byte_length = 4
}

resource "aws_iam_role" "cross_account_target_no_trust" {
  provider = aws.target
  name     = random_id.cross_account_target_no_trust_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect    = "Deny"
        Principal = { AWS = aws_iam_role.cross_account_principal.arn }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

output "cross_account_target_no_trust_arn" {
  value = aws_iam_role.cross_account_target_no_trust.arn
}

# ---------------------------------------------------------------------------
# Account B: EC2 instance for cross-account host discovery validation
# ---------------------------------------------------------------------------

data "aws_availability_zones" "target_azs" {
  count    = var.target_access_key_id != "" ? 1 : 0
  provider = aws.target
}

data "aws_ami" "target_ubuntu" {
  count       = var.target_access_key_id != "" ? 1 : 0
  provider    = aws.target
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_vpc" "target_vpc" {
  count                            = var.target_access_key_id != "" ? 1 : 0
  provider                         = aws.target
  cidr_block                       = "10.1.0.0/16"
  assign_generated_ipv6_cidr_block = true
}

resource "aws_subnet" "target_subnet" {
  count                           = var.target_access_key_id != "" ? 1 : 0
  provider                        = aws.target
  vpc_id                          = aws_vpc.target_vpc[0].id
  cidr_block                      = aws_vpc.target_vpc[0].cidr_block
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.target_vpc[0].ipv6_cidr_block, 8, 0)
  availability_zone               = data.aws_availability_zones.target_azs[0].names[0]
  map_public_ip_on_launch         = true
  assign_ipv6_address_on_creation = true
}

resource "aws_instance" "target_instances" {
  count         = var.target_access_key_id != "" ? length(local.instance_tags) : 0
  provider      = aws.target
  ami           = data.aws_ami.target_ubuntu[0].id
  instance_type = "t3.nano"
  subnet_id     = aws_subnet.target_subnet[0].id

  tags = local.instance_tags[count.index]
}

output "target_instance_ids" {
  value = aws_instance.target_instances.*.id
}

output "target_instance_tags" {
  value = {
    for _, r in aws_instance.target_instances : r.id => r.tags
  }
}
