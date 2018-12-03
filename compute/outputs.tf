#-----compute/outputs.tf

output "kmaster_id" {
  value = "${join(", ", aws_instance.kmaster.*.id)}"
}

output "kmaster_ip" {
  value = "${join(", ", aws_instance.kmaster.*.public_ip)}"
}

output "kminion_id" {
  value = "${join(", ", aws_instance.kminion.*.id)}"
}

output "kminion_ip" {
  value = "${join(", ", aws_instance.kminion.*.public_ip)}"
}
