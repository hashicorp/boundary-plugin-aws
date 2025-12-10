# Copyright IBM Corp. 2021, 2025
# SPDX-License-Identifier: MPL-2.0

resource "random_id" "foo" {
  byte_length = 2
  prefix      = "test-foo"
}

output "random_id_decimal" {
  value = random_id.foo.dec
}
