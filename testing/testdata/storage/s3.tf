# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "aws_s3_bucket" "test" {
  bucket        = random_id.prefix.dec
  force_destroy = true
  acl           = "private"
}