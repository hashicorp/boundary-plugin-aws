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

  tags = var.project_path_tags
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
}

resource "aws_iam_user_policy_attachement" "user_ec2_describeinstances_attachment" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.ec2_describeinstancest.arn
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
}

resource "aws_iam_user_policy_attachement" "user_self_manage_policy_attachment" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.user_self_manage_policy.arn
}
