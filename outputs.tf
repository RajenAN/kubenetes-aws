#----root/outputs.kube-----

#----storage outputs------

output "Bucket Name" {
  value = "${module.storage.bucketname}"
}

#---Networking Outputs -----

output "Public Subnets" {
  value = "${join(", ", module.networking.public_subnets)}"
}

output "Subnet IPs" {
  value = "${join(", ", module.networking.subnet_ips)}"
}

output "Public Security Group" {
  value = "${module.networking.public_sg}"
}

#---Compute Outputs ------

output "Kmaster Public Instance IDs" {
  value = "${module.compute.kmaster_id}"
}

output "Kmaster Public Instance IPs" {
  value = "${module.compute.kmaster_ip}"
}

output "Kminion Public Instance IDs" {
  value = "${module.compute.kminion_id}"
}

output "Kminion Public Instance IPs" {
  value = "${module.compute.kminion_ip}"
}
