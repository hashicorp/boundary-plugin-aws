# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "instance_tags" {
  default = [
    {
      "foo" = "true",
    },
    {
      "foo" = "true",
      "bar" = "true",
    },
    {
      "bar" = "true",
    },
    {
      "bar" = "true",
      "baz" = "true",
    },
    {
      "baz" = "true",
    },
  ]
}

data "aws_availability_zones" "azs" {}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "subnet" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = aws_vpc.vpc.cidr_block
  availability_zone = data.aws_availability_zones.azs.names[0]
}

resource "aws_instance" "instances" {
  count         = length(var.instance_tags)
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.nano"
  subnet_id     = aws_subnet.subnet.id

  tags = var.instance_tags[count.index]
}

output "instance_ids" {
  value = aws_instance.instances.*.id
}

output "instance_addrs" {
  value = {
    for _, r in aws_instance.instances : r.id => r.private_ip
  }
}

output "instance_tags" {
  value = {
    for _, r in aws_instance.instances : r.id => r.tags
  }
}