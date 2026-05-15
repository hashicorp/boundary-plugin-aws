# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

data "aws_caller_identity" "current" {}

variable "iam_user_count" {
  default = 6
}

# We are using a shared account for testing so make sure the stale ec2
# machine tags don't match for this test run
resource "random_id" "foo_key" {
  prefix      = "foo"
  byte_length = 4
}

resource "random_id" "bar_key" {
  prefix      = "bar"
  byte_length = 4
}

resource "random_id" "baz_key" {
  prefix      = "baz"
  byte_length = 4
}

locals {
  hashicorp_email = split(":", data.aws_caller_identity.current.user_id)[1]

  instance_tags = [
    {
      "${random_id.foo_key.dec}" = "true"
    },
    {
      "${random_id.foo_key.dec}" = "true"
      "${random_id.bar_key.dec}" = "true"
    },
    {
      "${random_id.bar_key.dec}" = "true"
    },
    {
      "${random_id.bar_key.dec}" = "true"
      "${random_id.baz_key.dec}" = "true"
    },
    {
      "${random_id.baz_key.dec}" = "true"
    },
  ]
}
