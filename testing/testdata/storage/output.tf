# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "bucket_name" {
  value = aws_s3_bucket.test.id
}

output "valid_policy_arn" {
    value = aws_iam_role.valid.arn
}

output "missing_put_obj_policy_arn" {
    value = aws_iam_role.missing_put_obj.arn
}

output "missing_get_obj_policy_arn" {
    value = aws_iam_role.missing_get_obj.arn
}

output "missing_delete_obj_policy_arn" {
    value = aws_iam_role.missing_delete_obj.arn
}

output "iam_user_names" {
  value = aws_iam_user.test.*.name
}

output "iam_user_arns" {
  value = aws_iam_user.test.*.arn
}

output "iam_access_key_ids" {
  value     = aws_iam_access_key.test.*.id
  sensitive = true
}

output "iam_secret_access_keys" {
  value     = aws_iam_access_key.test.*.secret
  sensitive = true
}

output "iam_access_key_missing_put_obj" {
  value     = aws_iam_access_key.missing_put_obj.id
  sensitive = true
}

output "iam_secret_access_key_missing_put_obj" {
  value     = aws_iam_access_key.missing_put_obj.secret
  sensitive = true
}

output "iam_access_key_missing_get_obj" {
  value     = aws_iam_access_key.missing_get_obj.id
  sensitive = true
}

output "iam_secret_access_key_missing_get_obj" {
  value     = aws_iam_access_key.missing_get_obj.secret
  sensitive = true
}

output "iam_access_key_missing_delete_obj" {
  value     = aws_iam_access_key.missing_delete_obj.id
  sensitive = true
}

output "iam_secret_access_key_missing_delete_obj" {
  value     = aws_iam_access_key.missing_delete_obj.secret
  sensitive = true
}