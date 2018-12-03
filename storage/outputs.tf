output "bucketname" {
  value = "${aws_s3_bucket.kube_code.id}"
}
