variable "iam_user_prefix" {
  default = "boundary-plugin-host-aws-test-iam-user"
}

resource "random_id" "aws_iam_user_name" {
  prefix      = var.iam_user_prefix
  byte_length = 4
}

resource "aws_iam_user" "user" {
  name = random_id.aws_iam_user_name.dec

  tags = var.project_path_tags
}

resource "aws_iam_access_key" "user_initial_key" {
  user = aws_iam_user.user.name
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
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.ec2_describeinstances.arn
}

resource "aws_iam_policy" "user_self_manage_policy" {
  name = "BoundaryPluginHostAwsTestUserSelfManagePolicy"

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
      "Resource": "${aws_iam_user.user.arn}"
    }
  ]
}
EOF

  tags = var.project_path_tags
}

resource "aws_iam_user_policy_attachment" "user_self_manage_policy_attachment" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.user_self_manage_policy.arn
}

output "iam_user_name" {
  value = aws_iam_user.user.name
}

output "iam_user_arn" {
  value = aws_iam_user.user.arn
}

output "iam_access_key_id" {
  value     = aws_iam_access_key.user_initial_key.id
  sensitive = true
}

output "iam_secret_access_key" {
  value     = aws_iam_access_key.user_initial_key.secret
  sensitive = true
}
