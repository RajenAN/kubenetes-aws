resource "null_resource" "kmaster" {
  # Changes to any instance of the cluster requires re-provisioning
  count = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.tf_server.*.id[0],aws_instance.tf_server.*.id[count.index])}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host = "${element(aws_instance.tf_server.*.public_ip, count.index)}"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [
      "cat ${join(" ", aws_instance.tf_server.*.private_ip[0], aws_instance.tf_server.*.private_ip[1])} > /tmp/ips",
    ]
  }
}
