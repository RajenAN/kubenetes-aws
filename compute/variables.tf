#-----compute/variables.tf

variable "key_name" {}

variable "public_key_path" {}

variable "subnet_ips" {
  type = "list"
}

variable "instance_count" {}

variable "instance_type" {}

variable "security_group" {}

variable "ep_count" {}

variable "subnets" {
  type = "list"
}
