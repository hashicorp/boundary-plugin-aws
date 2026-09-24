# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

resource "random_id" "assume_role_name" {
  prefix      = "BoundaryPluginAssumeRole"
  byte_length = 4
}

resource "aws_iam_role" "assume_role" {
  name = random_id.assume_role_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
      },
      # Also trusted by the cross-role principal role so it can be used
      # as the target in two-hop AssumeRole tests.
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.cross_role_principal.arn
        }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_role_policy_attachment" "assume_role_ec2_describeinstances" {
  role       = aws_iam_role.assume_role.name
  policy_arn = aws_iam_policy.ec2_describeinstances.arn
}

output "assume_role_arn" {
  value = aws_iam_role.assume_role.arn
}

# Error case: role exists with ec2:DescribeInstances but trust policy
# does not allow the caller to assume it.
resource "random_id" "assume_role_no_trust_name" {
  prefix      = "BoundaryPluginNoTrust"
  byte_length = 4
}

resource "aws_iam_role" "assume_role_no_trust" {
  name = random_id.assume_role_no_trust_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Deny"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

output "assume_role_no_trust_arn" {
  value = aws_iam_role.assume_role_no_trust.arn
}

# Error case: role exists and the caller can assume it, but has no
# ec2:DescribeInstances permission.
# Also trusted by cross_role_principal so this same role can be reused as the
# no-EC2-permission target in two-hop (cross-role) error case tests.
resource "random_id" "assume_role_no_ec2_permission_name" {
  prefix      = "BoundaryPluginNoEC2Perm"
  byte_length = 4
}

resource "aws_iam_role" "assume_role_no_ec2_permission" {
  name = random_id.assume_role_no_ec2_permission_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
      },
      # Also trusted by the cross-role principal so it can serve as the
      # no-EC2-permission target in two-hop error case tests.
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.cross_role_principal.arn
        }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

output "assume_role_no_ec2_permission_arn" {
  value = aws_iam_role.assume_role_no_ec2_permission.arn
}

# Cross-role (two-hop) principal role.
# The test runner can assume this role. It has permission to AssumeRole into
# aws_iam_role.assume_role (the target role) but has no ec2:DescribeInstances
# of its own. This simulates the principal side of a two-hop role chain: the
# plugin must assume the principal first, then use those credentials to assume
# the target role before calling DescribeInstances.
# Note: both roles are in the same AWS account. This tests the plugin's
# two-hop credential chain logic without requiring a second account.
resource "random_id" "cross_role_principal_name" {
  prefix      = "BoundaryPluginCRPrincipal"
  byte_length = 4
}

resource "aws_iam_role" "cross_role_principal" {
  name = random_id.cross_role_principal_name.dec

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
      },
    ]
  })

  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

# Single policy granting cross_role_principal permission to assume all target
# roles it needs for both happy path and error case tests.
resource "aws_iam_policy" "cross_role_principal_assume_targets" {
  name = "${random_id.cross_role_principal_name.dec}-assume-targets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Effect = "Allow"
        Resource = [
          aws_iam_role.assume_role.arn,
          aws_iam_role.assume_role_no_ec2_permission.arn,
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_role_principal_assume_targets" {
  role       = aws_iam_role.cross_role_principal.name
  policy_arn = aws_iam_policy.cross_role_principal_assume_targets.arn
}

output "cross_role_principal_arn" {
  value = aws_iam_role.cross_role_principal.arn
}

# Error case: caller cannot assume the principal role (first hop denied).
# Reuses assume_role_no_trust — it already has a Deny trust policy for the
# caller, so it also serves as an unassumable principal in two-hop tests.
output "cross_role_principal_no_trust_arn" {
  value = aws_iam_role.assume_role_no_trust.arn
}

# Error case: principal can be assumed, but the target role's trust policy
# does not allow the principal to assume it (second hop denied).
# Reuses assume_role_no_trust as the target — its Deny trust policy blocks
# all callers including cross_role_principal.
output "cross_role_target_no_trust_arn" {
  value = aws_iam_role.assume_role_no_trust.arn
}

# Error case: both hops succeed but the target has no ec2:DescribeInstances.
# Reuses assume_role_no_ec2_permission — its trust policy allows
# cross_role_principal (see above), and it has no EC2 permission.
output "cross_role_target_no_ec2_permission_arn" {
  value = aws_iam_role.assume_role_no_ec2_permission.arn
}
