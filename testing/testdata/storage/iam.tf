# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "aws_iam_role" "valid" {
  name = "${random_id.prefix.dec}-valid"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS: data.aws_caller_identity.current.user_id
        }
      },
    ]
  })
}

resource "aws_iam_policy" "valid" {
  name = "${random_id.prefix.dec}-valid"
  tags = local.tags

  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:GetObjectAttributes",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.test.arn}*"
    }
  ]

}
EOT
}

resource "aws_iam_role_policy_attachment" "valid" {
  role       = aws_iam_role.valid.name
  policy_arn = aws_iam_policy.valid.arn
}

resource "aws_iam_role" "missing_put_obj" {
  name = "${random_id.prefix.dec}-missing-put-obj"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS: data.aws_caller_identity.current.user_id
        }
      },
    ]
  })
}


resource "aws_iam_policy" "missing_put_obj" {
  name = "${random_id.prefix.dec}-missing-put-obj"
  tags = local.tags

  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetObject",
        "s3:GetObjectAttributes",
        "s3:ListBucket",
        "s3:DeleteObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.test.arn}*"
    }
  ]

}
EOT
}

resource "aws_iam_role_policy_attachment" "missing_put_obj" {
  role       = aws_iam_role.missing_put_obj.name
  policy_arn = aws_iam_policy.missing_put_obj.arn
}

resource "aws_iam_role" "missing_get_obj" {
  name = "${random_id.prefix.dec}-missing-get-obj"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS: data.aws_caller_identity.current.user_id
        }
      },
    ]
  })
}

resource "aws_iam_policy" "missing_get_obj" {
  name = "${random_id.prefix.dec}-missing-get-obj"
  tags = local.tags

  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.test.arn}*"
    }
  ]

}
EOT
}

resource "aws_iam_role_policy_attachment" "missing_get_obj" {
  role       = aws_iam_role.missing_get_obj.name
  policy_arn = aws_iam_policy.missing_get_obj.arn
}

resource "aws_iam_role" "missing_delete_obj" {
  name = "${random_id.prefix.dec}-missing-delete-obj"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS: data.aws_caller_identity.current.user_id
        }
      },
    ]
  })
}

resource "aws_iam_policy" "missing_delete_obj" {
  name = "${random_id.prefix.dec}-missing-delete-obj"
  tags = local.tags

  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectAttributes",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.test.arn}*"
    }
  ]

}
EOT
}

resource "aws_iam_role_policy_attachment" "missing_delete_obj" {
  role       = aws_iam_role.missing_delete_obj.name
  policy_arn = aws_iam_policy.missing_delete_obj.arn
}

# Static Credential Testing
resource "random_id" "user_name" {
  count       = var.iam_user_count
  prefix      = "demo-${local.hashicorp_email}-boundary-iam-user"
  byte_length = 4
}

resource "aws_iam_user" "test" {
  count                = var.iam_user_count
  name                 = random_id.user_name[count.index].dec
  force_destroy        = true
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/DemoUser"
  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_access_key" "test" {
  count = var.iam_user_count
  user  = aws_iam_user.test[count.index].name
}

resource "aws_iam_user_policy_attachment" "test_s3" {
  count      = var.iam_user_count
  user       = aws_iam_user.test[count.index].name
  policy_arn = aws_iam_policy.valid.arn
}

resource "aws_iam_policy" "credentials" {
  count = var.iam_user_count
  name  = aws_iam_user.test[count.index].name
  tags  = local.tags

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
      "Resource": "${aws_iam_user.test[count.index].arn}"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "test_credentials" {
  count      = var.iam_user_count
  user       = aws_iam_user.test[count.index].name
  policy_arn = aws_iam_policy.credentials[count.index].arn
}

# Edge case for missing DeleteObject permission
resource "random_id" "missing_delete_obj" {
  prefix      =  "demo-${local.hashicorp_email}-boundary-iam-user"
  byte_length = 4
}

resource "aws_iam_user" "missing_delete_obj" {
  name          = random_id.missing_delete_obj.dec
  force_destroy = true
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/DemoUser"
  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_access_key" "missing_delete_obj" {
  user  = aws_iam_user.missing_delete_obj.name
}

resource "aws_iam_user_policy_attachment" "missing_delete_obj" {
  user       = aws_iam_user.missing_delete_obj.name
  policy_arn = aws_iam_policy.missing_delete_obj.arn
}

# Edge case for missing GetObject permission

resource "random_id" "missing_get_obj" {
  prefix      =  "demo-${local.hashicorp_email}-boundary-iam-user"
  byte_length = 4
}

resource "aws_iam_user" "missing_get_obj" {
  name          = random_id.missing_get_obj.dec
  force_destroy = true
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/DemoUser"
  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_access_key" "missing_get_obj" {
  user  = aws_iam_user.missing_get_obj.name
}

resource "aws_iam_user_policy_attachment" "missing_get_obj" {
  user       = aws_iam_user.missing_get_obj.name
  policy_arn = aws_iam_policy.missing_get_obj.arn
}

# Edge case for missing PutObject permission

resource "random_id" "missing_put_obj" {
  prefix      =  "demo-${local.hashicorp_email}-boundary-iam-user"
  byte_length = 4
}

resource "aws_iam_user" "missing_put_obj" {
  name          = random_id.missing_put_obj.dec
  force_destroy = true
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/DemoUser"
  tags = {
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_iam_access_key" "missing_put_obj" {
  user  = aws_iam_user.missing_put_obj.name
}

resource "aws_iam_user_policy_attachment" "missing_put_obj" {
  user       = aws_iam_user.missing_put_obj.name
  policy_arn = aws_iam_policy.missing_put_obj.arn
}