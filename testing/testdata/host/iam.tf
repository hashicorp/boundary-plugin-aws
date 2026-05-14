# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

resource "random_id" "aws_iam_user_name" {
  count       = var.iam_user_count
  prefix      = "demo-${local.hashicorp_email}-boundary-iam-user"
  byte_length = 4
}

resource "aws_iam_user" "user" {
  count                = var.iam_user_count
  name                 = random_id.aws_iam_user_name[count.index].dec
  force_destroy        = true
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/DemoUser"
  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_access_key" "user_initial_key" {
  count = var.iam_user_count
  user  = aws_iam_user.user[count.index].name
}

resource "random_id" "aws_ec2_policy_name" {
  prefix      = "BoundaryPluginHost"
  byte_length = 4
}

resource "aws_iam_policy" "ec2_describeinstances" {
  name = random_id.aws_ec2_policy_name.dec

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "user_ec2_describeinstances_attachment" {
  count      = var.iam_user_count
  user       = aws_iam_user.user[count.index].name
  policy_arn = aws_iam_policy.ec2_describeinstances.arn
}

resource "random_id" "aws_iam_policy_name" {
  count       = var.iam_user_count
  prefix      = "BoundaryPluginCredentials"
  byte_length = 4
}

resource "aws_iam_policy" "user_self_manage_policy" {
  count = var.iam_user_count
  name  = random_id.aws_iam_policy_name[count.index].dec

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "iam:DeleteAccessKey",
        "iam:GetUser",
        "iam:CreateAccessKey"
      ],
      "Effect": "Allow",
      "Resource": "${aws_iam_user.user[count.index].arn}"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "user_self_manage_policy_attachment" {
  count      = var.iam_user_count
  user       = aws_iam_user.user[count.index].name
  policy_arn = aws_iam_policy.user_self_manage_policy[count.index].arn
}

output "iam_user_names" {
  value = aws_iam_user.user.*.name
}

output "iam_user_arns" {
  value = aws_iam_user.user.*.arn
}

output "iam_access_key_ids" {
  value     = aws_iam_access_key.user_initial_key.*.id
  sensitive = true
}

output "iam_secret_access_keys" {
  value     = aws_iam_access_key.user_initial_key.*.secret
  sensitive = true
}