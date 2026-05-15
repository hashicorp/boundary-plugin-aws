# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

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
  cidr_block                       = "10.0.0.0/16"
  assign_generated_ipv6_cidr_block = true
}

resource "aws_subnet" "subnet" {
  vpc_id                          = aws_vpc.vpc.id
  cidr_block                      = aws_vpc.vpc.cidr_block
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.vpc.ipv6_cidr_block, 8, 0)
  availability_zone               = data.aws_availability_zones.azs.names[0]
  map_public_ip_on_launch         = true
  assign_ipv6_address_on_creation = true
}

# Need to add a gateway for public IP addr assignments 
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.subnet.id
  route_table_id = aws_route_table.public.id
}

resource "aws_instance" "instances" {
  count         = length(local.instance_tags)
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.nano"
  subnet_id     = aws_subnet.subnet.id

  tags = local.instance_tags[count.index]
}

resource "aws_instance" "multi_address_instance" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.nano"
  subnet_id                   = aws_subnet.subnet.id
  secondary_private_ips       = ["10.0.10.10"]
  ipv6_address_count          = 1
  associate_public_ip_address = true

  tags = {
    Name            = "boundary-multi-address-instance"
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_network_interface" "multi_address_secondary_eni" {
  subnet_id      = aws_subnet.subnet.id
  private_ips    = ["10.0.20.10"]
  ipv6_addresses = [cidrhost(aws_subnet.subnet.ipv6_cidr_block, 32)]

  tags = {
    Name            = "boundary-multi-address-secondary-eni"
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_network_interface_attachment" "multi_address_secondary_eni" {
  instance_id          = aws_instance.multi_address_instance.id
  network_interface_id = aws_network_interface.multi_address_secondary_eni.id
  device_index         = 1
}

resource "aws_eip" "multi_address_primary" {
  domain                    = "vpc"
  network_interface         = aws_instance.multi_address_instance.primary_network_interface_id
  associate_with_private_ip = aws_instance.multi_address_instance.private_ip
  depends_on                = [aws_internet_gateway.igw, aws_route_table_association.public]

  tags = {
    Name            = "boundary-multi-address-primary-eip"
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_eip" "multi_address_primary_secondary_private" {
  domain                    = "vpc"
  network_interface         = aws_instance.multi_address_instance.primary_network_interface_id
  associate_with_private_ip = "10.0.10.10"
  depends_on                = [aws_internet_gateway.igw, aws_route_table_association.public, aws_instance.multi_address_instance]

  tags = {
    Name            = "boundary-multi-address-primary-secondary-eip"
    "boundary-demo" = local.hashicorp_email
  }
}

resource "aws_eip" "multi_address_secondary_eni" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.multi_address_secondary_eni.id
  associate_with_private_ip = "10.0.20.10"
  depends_on                = [aws_internet_gateway.igw, aws_route_table_association.public, aws_network_interface_attachment.multi_address_secondary_eni]

  tags = {
    Name            = "boundary-multi-address-secondary-eni-eip"
    "boundary-demo" = local.hashicorp_email
  }
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

output "instance_tag_keys" {
  value = [
    random_id.foo_key.dec,
    random_id.bar_key.dec,
    random_id.baz_key.dec,
  ]
}

output "multi_address_instance_id" {
  value = aws_instance.multi_address_instance.id
}

output "multi_address_primary_addresses" {
  value = {
    private_ip = aws_instance.multi_address_instance.private_ip
    public_ip  = aws_eip.multi_address_primary.public_ip
    ipv6       = tolist(aws_instance.multi_address_instance.ipv6_addresses)[0]
  }
}

output "multi_address_secondary_addresses" {
  value = {
    primary_eni_private_ip   = "10.0.10.10"
    primary_eni_public_ip    = aws_eip.multi_address_primary_secondary_private.public_ip
    secondary_eni_private_ip = aws_network_interface.multi_address_secondary_eni.private_ip
    secondary_eni_public_ip  = aws_eip.multi_address_secondary_eni.public_ip
    secondary_eni_ipv6       = tolist(aws_network_interface.multi_address_secondary_eni.ipv6_addresses)[0]
  }
}

