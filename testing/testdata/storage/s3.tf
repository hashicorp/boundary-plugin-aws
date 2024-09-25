# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "aws_s3_bucket" "test" {
  bucket        = random_id.prefix.dec
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "secure_access" {
  bucket = aws_s3_bucket.test.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}