#-----compute/main.kube

data "aws_ami" "server_ami" {
  most_recent = true

  #filter {
  #  name   = "owner-alias"
  #  values = ["amazon"]
  #}

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20180912"]
  }
}

resource "aws_key_pair" "kube_auth" {
  key_name   = "${var.key_name}"
  public_key = "${file(var.public_key_path)}"
}

data "template_file" "user-init" {
  count    = "${var.instance_count}"
  template = "${file("${path.module}/userdata.tpl")}"

  vars {
    firewall_subnets = "${element(var.subnet_ips, count.index)}"
  }
}

resource "aws_instance" "kmaster" {
  count         = 2
  instance_type = "${var.instance_type}"
  ami           = "${data.aws_ami.server_ami.id}"

  tags {
    Name = "kmaster-${count.index +1}"
  }

  key_name               = "${aws_key_pair.kube_auth.id}"
  vpc_security_group_ids = ["${var.security_group}"]
  subnet_id              = "${element(var.subnets, count.index)}"
  user_data              = "${data.template_file.user-init.*.rendered[count.index]}"

  #public_ip              = "${element(aws_eip.lb.public_ip,count.index)}"
}

resource "aws_instance" "kminion" {
  count         = 2
  instance_type = "${var.instance_type}"
  ami           = "${data.aws_ami.server_ami.id}"

  tags {
    Name = "kminion-${count.index +1}"
  }

  key_name               = "${aws_key_pair.kube_auth.id}"
  vpc_security_group_ids = ["${var.security_group}"]
  subnet_id              = "${element(var.subnets, count.index)}"
  user_data              = "${data.template_file.user-init.*.rendered[count.index]}"

  #public_ip              = "${element(aws_eip.lb.public_ip,count.index)}"
}

#resource "aws_eip" "lb" {
#  depends_on = ["aws_instance.kmaster"]
#  count      = "${var.ep_count}"
#  instance   = "${aws_instance.kmaster.*.id[count.index]}"
#  vpc        = true
#}

resource "null_resource" "cert_create" {
  depends_on = ["aws_instance.kmaster"]

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kmaster.*.id)}"
  }

  provisioner "local-exec" {
    command = <<EOT
  mkdir -p ~/kubenetes_cert
  cd ~/kubenetes_cert

  {

cat > ca-config.json << EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF

cat > ca-csr.json << EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca

}

  {

cat > admin-csr.json << EOF
{
  "CN": "admin",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:masters",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  admin-csr.json | cfssljson -bare admin

}


{

cat > admin-csr.json << EOF
{
  "CN": "admin",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:masters",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  admin-csr.json | cfssljson -bare admin

}

{

cat > kube-controller-manager-csr.json << EOF
{
  "CN": "system:kube-controller-manager",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:kube-controller-manager",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager

}

{

cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:node-proxier",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-proxy-csr.json | cfssljson -bare kube-proxy

}

{

cat > kube-scheduler-csr.json << EOF
{
  "CN": "system:kube-scheduler",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:kube-scheduler",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-scheduler-csr.json | cfssljson -bare kube-scheduler

}

CERT_HOSTNAME=10.32.0.1,${aws_instance.kmaster.*.private_ip[0]},${aws_instance.kmaster.*.public_dns[0]},${aws_instance.kmaster.*.private_ip[1]},${aws_instance.kmaster.*.public_dns[1]},127.0.0.1,localhost,kubernetes.default

{

cat > kubernetes-csr.json << EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=$${CERT_HOSTNAME} \
  -profile=kubernetes \
  kubernetes-csr.json | cfssljson -bare kubernetes

}

{

cat > service-account-csr.json << EOF
{
  "CN": "service-accounts",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  service-account-csr.json | cfssljson -bare service-account

}
EOT
  }
}

resource "null_resource" "kubectl_cert_create" {
  depends_on = ["null_resource.cert_create"]

  triggers {
    kminion_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  provisioner "local-exec" {
    command = <<EOT
  mkdir -p ~/kubenetes_cert
  cd ~/kubenetes_cert

  WORKER0_HOST=${aws_instance.kminion.*.public_dns[0]}
WORKER0_IP=${aws_instance.kminion.*.private_ip[0]}
WORKER1_HOST=${aws_instance.kminion.*.public_dns[1]}
WORKER1_IP=${aws_instance.kminion.*.private_ip[1]}

{
cat > $${WORKER0_HOST}-csr.json << EOF
{
  "CN": "system:node:$${WORKER0_HOST}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:nodes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=$${WORKER0_IP},$${WORKER0_HOST} \
  -profile=kubernetes \
  $${WORKER0_HOST}-csr.json | cfssljson -bare $${WORKER0_HOST}

cat > $${WORKER1_HOST}-csr.json << EOF
{
  "CN": "system:node:$${WORKER1_HOST}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:nodes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=$${WORKER1_IP},$${WORKER1_HOST} \
  -profile=kubernetes \
  $${WORKER1_HOST}-csr.json | cfssljson -bare $${WORKER1_HOST}

}

sleep 60
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem ${aws_instance.kminion.*.public_dns[0]}-key.pem ${aws_instance.kminion.*.public_dns[0]}.pem ubuntu@${aws_instance.kminion.*.public_dns[0]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem ${aws_instance.kminion.*.public_dns[1]}-key.pem ${aws_instance.kminion.*.public_dns[1]}.pem ubuntu@${aws_instance.kminion.*.public_dns[1]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem service-account-key.pem service-account.pem ubuntu@${aws_instance.kmaster.*.public_dns[0]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem service-account-key.pem service-account.pem ubuntu@${aws_instance.kmaster.*.public_dns[1]}:~/
EOT
  }
}

resource "null_resource" "kubeconfig_create" {
  depends_on = ["null_resource.kubectl_cert_create"]

  triggers {
    kminion_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  provisioner "local-exec" {
    command = <<EOT
  mkdir -p ~/kubenetes_cert
  cd ~/kubenetes_cert

KUBERNETES_ADDRESS=${aws_instance.kmaster.*.private_ip[0]}
WORKER0_IP=${aws_instance.kminion.*.public_dns[0]}
WORKER1_IP=${aws_instance.kminion.*.public_dns[1]}
{
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.pem \
  --embed-certs=true \
  --server=https://$${KUBERNETES_ADDRESS}:6443 \
  --kubeconfig=$${WORKER0_IP}.kubeconfig

kubectl config set-credentials system:node:$${WORKER0_IP} \
  --client-certificate=$${WORKER0_IP}.pem \
  --client-key=$${WORKER0_IP}-key.pem \
  --embed-certs=true \
  --kubeconfig=$${WORKER0_IP}.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=system:node:$${WORKER0_IP} \
  --kubeconfig=$${WORKER0_IP}.kubeconfig

kubectl config use-context default --kubeconfig=$${WORKER0_IP}.kubeconfig
}
{
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.pem \
  --embed-certs=true \
  --server=https://$${KUBERNETES_ADDRESS}:6443 \
  --kubeconfig=$${WORKER1_IP}.kubeconfig

kubectl config set-credentials system:node:$${WORKER1_IP} \
  --client-certificate=$${WORKER1_IP}.pem \
  --client-key=$${WORKER1_IP}-key.pem \
  --embed-certs=true \
  --kubeconfig=$${WORKER1_IP}.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=system:node:$${WORKER1_IP} \
  --kubeconfig=$${WORKER1_IP}.kubeconfig

kubectl config use-context default --kubeconfig=$${WORKER1_IP}.kubeconfig
}

{
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://$${KUBERNETES_ADDRESS}:6443 \
    --kubeconfig=kube-proxy.kubeconfig

  kubectl config set-credentials system:kube-proxy \
    --client-certificate=kube-proxy.pem \
    --client-key=kube-proxy-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-proxy.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-proxy \
    --kubeconfig=kube-proxy.kubeconfig

  kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
}

{
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=kube-controller-manager.kubeconfig

  kubectl config set-credentials system:kube-controller-manager \
    --client-certificate=kube-controller-manager.pem \
    --client-key=kube-controller-manager-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-controller-manager.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-controller-manager \
    --kubeconfig=kube-controller-manager.kubeconfig

  kubectl config use-context default --kubeconfig=kube-controller-manager.kubeconfig
}

{
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=kube-scheduler.kubeconfig

  kubectl config set-credentials system:kube-scheduler \
    --client-certificate=kube-scheduler.pem \
    --client-key=kube-scheduler-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-scheduler.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-scheduler \
    --kubeconfig=kube-scheduler.kubeconfig

  kubectl config use-context default --kubeconfig=kube-scheduler.kubeconfig
}

{
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=admin.kubeconfig

  kubectl config set-credentials admin \
    --client-certificate=admin.pem \
    --client-key=admin-key.pem \
    --embed-certs=true \
    --kubeconfig=admin.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=admin \
    --kubeconfig=admin.kubeconfig

  kubectl config use-context default --kubeconfig=admin.kubeconfig
}
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem ${aws_instance.kminion.*.public_dns[0]}.kubeconfig kube-proxy.kubeconfig ubuntu@${aws_instance.kminion.*.public_dns[0]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem ${aws_instance.kminion.*.public_dns[1]}.kubeconfig kube-proxy.kubeconfig ubuntu@${aws_instance.kminion.*.public_dns[1]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem admin.kubeconfig kube-controller-manager.kubeconfig kube-scheduler.kubeconfig ubuntu@${aws_instance.kmaster.*.public_dns[0]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa ca.pem admin.kubeconfig kube-controller-manager.kubeconfig kube-scheduler.kubeconfig ubuntu@${aws_instance.kmaster.*.public_dns[1]}:~/

EOT
  }
}

resource "null_resource" "kubedataencrypt_create" {
  depends_on = ["null_resource.kubectl_cert_create"]

  triggers {
    kminion_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  provisioner "local-exec" {
    command = <<EOT
  mkdir -p ~/kubenetes_cert
  cd ~/kubenetes_cert
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
cat > encryption-config.yaml << EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: $${ENCRYPTION_KEY}
      - identity: {}
EOF
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa encryption-config.yaml ubuntu@${aws_instance.kmaster.*.public_dns[0]}:~/
scp -o "StrictHostKeyChecking no" -i ~/.ssh/id_rsa encryption-config.yaml ubuntu@${aws_instance.kmaster.*.public_dns[1]}:~/

EOT
  }
}

resource "null_resource" "etcd_provision" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kubedataencrypt_create"]
  count      = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kmaster.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kmaster.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT
wget -q --show-progress --https-only --timestamping "https://github.com/coreos/etcd/releases/download/v3.3.5/etcd-v3.3.5-linux-amd64.tar.gz"
 tar -xvf etcd-v3.3.5-linux-amd64.tar.gz
 sudo mv etcd-v3.3.5-linux-amd64/etcd* /usr/local/bin/
 sudo mkdir -p /etc/etcd /var/lib/etcd
 sudo cp ca.pem kubernetes-key.pem kubernetes.pem /etc/etcd/
 ETCD_NAME=$(curl http://169.254.169.254/latest/meta-data/public-hostname)
INTERNAL_IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
INITIAL_CLUSTER=${aws_instance.kmaster.*.public_dns[0]}=https://${aws_instance.kmaster.*.private_ip[0]}:2380,${aws_instance.kmaster.*.public_dns[1]}=https://${aws_instance.kmaster.*.private_ip[1]}:2380

cat << EOF | sudo tee /etc/systemd/system/etcd.service
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/local/bin/etcd \\
  --name $${ETCD_NAME} \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --initial-advertise-peer-urls https://$${INTERNAL_IP}:2380 \\
  --listen-peer-urls https://$${INTERNAL_IP}:2380 \\
  --listen-client-urls https://$${INTERNAL_IP}:2379,https://127.0.0.1:2379 \\
  --advertise-client-urls https://$${INTERNAL_IP}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster $${INITIAL_CLUSTER} \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable etcd
sudo systemctl start etcd
EOT
    ]
  }
}

resource "null_resource" "kubemaster_provision" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.etcd_provision"]
  count      = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kmaster.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kmaster.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT
      sudo mkdir -p /etc/kubernetes/config

      wget -q --show-progress --https-only --timestamping \
        "https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kube-apiserver" \
        "https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kube-controller-manager" \
        "https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kube-scheduler" \
        "https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kubectl"

      chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl

      sudo mv kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/local/bin/
      sudo mkdir -p /var/lib/kubernetes/

sudo cp ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem \
  service-account-key.pem service-account.pem \
  encryption-config.yaml /var/lib/kubernetes/
  INTERNAL_IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
  CONTROLLER0_IP=${aws_instance.kmaster.*.private_ip[0]}
CONTROLLER1_IP=${aws_instance.kmaster.*.private_ip[1]}
cat << EOF | sudo tee /etc/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-apiserver \\
  --advertise-address=$${INTERNAL_IP} \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/audit.log \\
  --authorization-mode=Node,RBAC \\
  --bind-address=0.0.0.0 \\
  --client-ca-file=/var/lib/kubernetes/ca.pem \\
  --enable-admission-plugins=Initializers,NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --enable-swagger-ui=true \\
  --etcd-cafile=/var/lib/kubernetes/ca.pem \\
  --etcd-certfile=/var/lib/kubernetes/kubernetes.pem \\
  --etcd-keyfile=/var/lib/kubernetes/kubernetes-key.pem \\
  --etcd-servers=https://$${CONTROLLER0_IP}:2379,https://$${CONTROLLER1_IP}:2379 \\
  --event-ttl=1h \\
  --experimental-encryption-provider-config=/var/lib/kubernetes/encryption-config.yaml \\
  --kubelet-certificate-authority=/var/lib/kubernetes/ca.pem \\
  --kubelet-client-certificate=/var/lib/kubernetes/kubernetes.pem \\
  --kubelet-client-key=/var/lib/kubernetes/kubernetes-key.pem \\
  --kubelet-https=true \\
  --runtime-config=api/all \\
  --service-account-key-file=/var/lib/kubernetes/service-account.pem \\
  --service-cluster-ip-range=10.32.0.0/24 \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --v=2 \\
  --kubelet-preferred-address-types=InternalIP,InternalDNS,Hostname,ExternalIP,ExternalDNS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo cp kube-controller-manager.kubeconfig /var/lib/kubernetes/

cat << EOF | sudo tee /etc/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-controller-manager \\
  --address=0.0.0.0 \\
  --cluster-cidr=10.200.0.0/16 \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/var/lib/kubernetes/ca.pem \\
  --cluster-signing-key-file=/var/lib/kubernetes/ca-key.pem \\
  --kubeconfig=/var/lib/kubernetes/kube-controller-manager.kubeconfig \\
  --leader-elect=true \\
  --root-ca-file=/var/lib/kubernetes/ca.pem \\
  --service-account-private-key-file=/var/lib/kubernetes/service-account-key.pem \\
  --service-cluster-ip-range=10.32.0.0/24 \\
  --use-service-account-credentials=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo cp kube-scheduler.kubeconfig /var/lib/kubernetes/

cat << EOF | sudo tee /etc/kubernetes/config/kube-scheduler.yaml
apiVersion: componentconfig/v1alpha1
kind: KubeSchedulerConfiguration
clientConnection:
  kubeconfig: "/var/lib/kubernetes/kube-scheduler.kubeconfig"
leaderElection:
  leaderElect: true
EOF

cat << EOF | sudo tee /etc/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-scheduler \\
  --config=/etc/kubernetes/config/kube-scheduler.yaml \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kube-apiserver kube-controller-manager kube-scheduler
sudo systemctl start kube-apiserver kube-controller-manager kube-scheduler
EOT
    ]
  }
}

resource "null_resource" "kubelet_rbac_auth" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kubemaster_provision"]
  count      = 1

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kmaster.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kmaster.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "file" {
    source      = "compute/kubeletclusterrole.yaml"
    destination = "/tmp/kubeletclusterrole.yaml"
  }

  provisioner "file" {
    source      = "compute/kubeletrolebinding.yaml"
    destination = "/tmp/kubeletrolebinding.yaml"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT
      sleep 30
      kubectl apply --kubeconfig admin.kubeconfig -f /tmp/kubeletclusterrole.yaml

      kubectl apply --kubeconfig admin.kubeconfig -f /tmp/kubeletrolebinding.yaml

EOT
    ]
  }
}

resource "null_resource" "kminion_binary_download" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kubelet_rbac_auth"]
  count      = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kminion.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT

      sudo apt-get -y install socat conntrack ipset

      wget -q --show-progress --https-only --timestamping \
        https://github.com/kubernetes-incubator/cri-tools/releases/download/v1.0.0-beta.0/crictl-v1.0.0-beta.0-linux-amd64.tar.gz \
        https://storage.googleapis.com/kubernetes-the-hard-way/runsc \
        https://github.com/opencontainers/runc/releases/download/v1.0.0-rc5/runc.amd64 \
        https://github.com/containernetworking/plugins/releases/download/v0.6.0/cni-plugins-amd64-v0.6.0.tgz \
        https://github.com/containerd/containerd/releases/download/v1.1.0/containerd-1.1.0.linux-amd64.tar.gz \
        https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kubectl \
        https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kube-proxy \
        https://storage.googleapis.com/kubernetes-release/release/v1.10.2/bin/linux/amd64/kubelet

      sudo mkdir -p \
        /etc/cni/net.d \
        /opt/cni/bin \
        /var/lib/kubelet \
        /var/lib/kube-proxy \
        /var/lib/kubernetes \
        /var/run/kubernetes

      chmod +x kubectl kube-proxy kubelet runc.amd64 runsc

      sudo mv runc.amd64 runc

      sudo mv kubectl kube-proxy kubelet runc runsc /usr/local/bin/

      sudo tar -xvf crictl-v1.0.0-beta.0-linux-amd64.tar.gz -C /usr/local/bin/

      sudo tar -xvf cni-plugins-amd64-v0.6.0.tgz -C /opt/cni/bin/

      sudo tar -xvf containerd-1.1.0.linux-amd64.tar.gz -C /

EOT
    ]
  }
}

resource "null_resource" "kminion_containerd_install" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kminion_binary_download"]
  count      = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kminion.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT
sudo mkdir -p /etc/containerd/
cat << EOF | sudo tee /etc/containerd/config.toml
[plugins]
  [plugins.cri.containerd]
    snapshotter = "overlayfs"
    [plugins.cri.containerd.default_runtime]
      runtime_type = "io.containerd.runtime.v1.linux"
      runtime_engine = "/usr/local/bin/runc"
      runtime_root = ""
    [plugins.cri.containerd.untrusted_workload_runtime]
      runtime_type = "io.containerd.runtime.v1.linux"
      runtime_engine = "/usr/local/bin/runsc"
      runtime_root = "/run/containerd/runsc"
EOF
cat << EOF | sudo tee /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=/sbin/modprobe overlay
ExecStart=/bin/containerd
Restart=always
RestartSec=5
Delegate=yes
KillMode=process
OOMScoreAdjust=-999
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF

EOT
    ]
  }
}

resource "null_resource" "kminion_kubelet_install" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kminion_containerd_install"]
  count      = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kminion.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "file" {
    source      = "compute/kubelet-config.yaml"
    destination = "/tmp/kubelet-config.yaml"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT
export HOSTNAME=$(curl http://169.254.169.254/latest/meta-data/public-hostname)
sudo mv $${HOSTNAME}-key.pem $${HOSTNAME}.pem /var/lib/kubelet/
sudo mv $${HOSTNAME}.kubeconfig /var/lib/kubelet/kubeconfig
sudo mv ca.pem /var/lib/kubernetes/
sudo mv /tmp/kubelet-config.yaml /var/lib/kubelet/kubelet-config.yaml
sudo sed -i "s/HOSTNAME/$${HOSTNAME}/g" /var/lib/kubelet/kubelet-config.yaml

cat << EOF | sudo tee /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=containerd.service
Requires=containerd.service

[Service]
ExecStart=/usr/local/bin/kubelet \\
  --config=/var/lib/kubelet/kubelet-config.yaml \\
  --container-runtime=remote \\
  --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock \\
  --image-pull-progress-deadline=2m \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --network-plugin=cni \\
  --register-node=true \\
  --v=2 \\
  --hostname-override=HOSTNAME \\
  --allow-privileged=true
   Restart=on-failure
   RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo sed -i "s/HOSTNAME/$${HOSTNAME}/g"  /etc/systemd/system/kubelet.service
EOT
    ]
  }
}

resource "null_resource" "kminion_kubeproxy_install" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kminion_kubelet_install"]
  count      = 2

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kminion.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kminion.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "file" {
    source      = "compute/kube-proxy-config.yaml"
    destination = "/tmp/kube-proxy-config.yaml"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT

sudo mv kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig
sudo mv /tmp/kube-proxy-config.yaml /var/lib/kube-proxy/kube-proxy-config.yaml
cat << EOF | sudo tee /etc/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Kube Proxy
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-proxy \\
  --config=/var/lib/kube-proxy/kube-proxy-config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable containerd kubelet kube-proxy
sudo systemctl start containerd kubelet kube-proxy
sudo sysctl net.ipv4.conf.all.forwarding=1
echo "net.ipv4.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
EOT
    ]
  }
}

resource "null_resource" "kminion_network_install" {
  # Changes to any instance of the cluster requires re-provisioning
  depends_on = ["null_resource.kminion_kubeproxy_install"]
  count      = 1

  triggers {
    kmaster_instance_ids = "${join(",", aws_instance.kmaster.*.id)}"
  }

  # Bootstrap script can run on any instance of the cluster
  # So we just choose the first in this case
  connection {
    host        = "${element(aws_instance.kmaster.*.public_ip, count.index)}"
    type        = "ssh"
    user        = "ubuntu"
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  provisioner "remote-exec" {
    # Bootstrap script called with private_ip of each node in the clutser
    inline = [<<EOT
sudo sysctl net.ipv4.conf.all.forwarding=1
echo "net.ipv4.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')&env.IPALLOC_RANGE=10.200.0.0/16" --kubeconfig admin.kubeconfig
kubectl create -f https://storage.googleapis.com/kubernetes-the-hard-way/kube-dns.yaml --kubeconfig admin.kubeconfig
EOT
    ]
  }
}
