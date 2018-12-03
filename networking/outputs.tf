#-----networking/outputs.kube

output "public_subnets" {
  value = "${aws_subnet.kube_public_subnet.*.id}"
}

output "public_sg" {
  value = "${aws_security_group.kube_public_sg.id}"
}

output "subnet_ips" {
  value = "${aws_subnet.kube_public_subnet.*.cidr_block}"
}
