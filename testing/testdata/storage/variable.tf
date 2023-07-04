# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "aws_caller_identity" "current" {}

resource "random_id" "prefix" {
  prefix      = "storage-e2e-test"
  byte_length = 4
}

variable "iam_user_count" {
  default = 6
}