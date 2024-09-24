# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "aws_caller_identity" "current" {}

resource "random_id" "prefix" {
  prefix      = "aws-plugin-e2e-test"
  byte_length = 4
}

variable "iam_user_count" {
  default = 6
}

locals {
  hashicorp_email = split(":", data.aws_caller_identity.current.user_id)[1]
  tags = {
    User        = split(":", data.aws_caller_identity.current.user_id)[1]
    Repo        = "boundary-plugin-aws" 
    Environment = "Demo"
  }
}
