variable "iam_user_prefix" {
  default = "boundary-plugin-host-aws-test-iam-user"
}

variable "iam_user_count" {
  default = 6
}

resource "random_id" "aws_iam_user_name" {
  count       = var.iam_user_count
  prefix      = "${var.iam_user_prefix}-${count.index}"
  byte_length = 4
}

resource "aws_iam_user" "user" {
  count         = var.iam_user_count
  name          = random_id.aws_iam_user_name[count.index].dec
  force_destroy = true

  tags = var.project_path_tags
}

resource "aws_iam_access_key" "user_initial_key" {
  count = var.iam_user_count
  user  = aws_iam_user.user[count.index].name
}

resource "aws_iam_policy" "ec2_describeinstances" {
  name = "BoundaryPluginHostAwsTestDescribeInstancesPolicy"

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

  tags = var.project_path_tags
}

resource "aws_iam_user_policy_attachment" "user_ec2_describeinstances_attachment" {
  count      = var.iam_user_count
  user       = aws_iam_user.user[count.index].name
  policy_arn = aws_iam_policy.ec2_describeinstances.arn
}

resource "aws_iam_policy" "user_self_manage_policy" {
  count = var.iam_user_count
  name  = "BoundaryPluginHostAwsTestUserSelfManagePolicy-${count.index}"

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

  tags = var.project_path_tags
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
