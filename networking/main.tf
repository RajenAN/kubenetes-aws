#----networking/main.kube

data "aws_availability_zones" "available" {}

resource "aws_vpc" "kube_vpc" {
  cidr_block           = "${var.vpc_cidr}"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags {
    Name = "kube_vpc"
  }
}

resource "aws_internet_gateway" "kube_internet_gateway" {
  vpc_id = "${aws_vpc.kube_vpc.id}"

  tags {
    Name = "kube_igw"
  }
}

resource "aws_route_table" "kube_public_rt" {
  vpc_id = "${aws_vpc.kube_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.kube_internet_gateway.id}"
  }

  tags {
    Name = "kube_public"
  }
}

resource "aws_default_route_table" "kube_private_rt" {
  default_route_table_id = "{aws_vpc.kube_vpc.default_route_table.id}"

  tags {
    Name = "kube_private"
  }
}

resource "aws_subnet" "kube_public_subnet" {
  count                   = 4
  vpc_id                  = "${aws_vpc.kube_vpc.id}"
  cidr_block              = "${var.public_cidrs[count.index]}"
  map_public_ip_on_launch = true
  availability_zone       = "${data.aws_availability_zones.available.names[count.index]}"

  tags {
    Name = "kube_public_${count.index + 1}"
  }
}

resource "aws_route_table_association" "kube_public_assoc" {
  count          = "${aws_subnet.kube_public_subnet.count}"
  subnet_id      = "${aws_subnet.kube_public_subnet.*.id[count.index]}"
  route_table_id = "${aws_route_table.kube_public_rt.id}"
}

resource "aws_security_group" "kube_public_sg" {
  name        = "kube_public_sg"
  description = "Used for access to the public instances"
  vpc_id      = "${aws_vpc.kube_vpc.id}"

  #SSH

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
