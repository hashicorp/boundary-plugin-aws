# Copyright IBM Corp. 2021, 2026
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

  # total number of objects of each type to create
  s3_pagination_test_object_count = 350
  # Dynamically build a flat map of S3 objects:
  # - root-level text files
  # - nested JSON files
  # - placeholder "empty directories"
  # - some static files in list-objects directory
  # This map is consumed directly by an aws_s3_object resource
  s3_files = merge(
    # Root-level text files
    {
      for i in range(local.s3_pagination_test_object_count) :
      "list-objects-paginated/root-file-${i}.txt" => "This is a root-level file #${i}."
    },

    # Nested JSON files inside sub-directories
    {
      for i in range(local.s3_pagination_test_object_count) :
      "list-objects-paginated/nested-dir-${i}/data-file-${i}.json" =>
      jsonencode({
        id      = i,
        message = "This is a nested JSON file #${i}."
      })
    },

    # "Empty" directories (in S3 these are just placeholder objects ending with `/`)
    {
      for i in range(local.s3_pagination_test_object_count) :
      "list-objects-paginated/empty-dir-${i}/dir-${i}/" => "" # zero-length object to mimic directory
    },

    # Static example files in list-objects directory
    {
      "list-objects/file1.txt"            = "This is the content for file 1."
      "list-objects/data.json"            = jsonencode({ key = "value", items = [1, 2, 3] })
      "list-objects/nested-dir/file2.txt" = "This is a nested file."
      "list-objects/empty-nested-dir/"    = ""
    }
  )
}
