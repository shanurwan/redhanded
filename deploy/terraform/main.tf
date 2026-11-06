# One Vultr VX1 VM runs the site, the scan worker, gVisor, Firecracker and the sinkhole.
# VX1 exposes /dev/kvm to guests, which is what the microVM tier needs.
# `terraform destroy` removes every billable thing this creates.

terraform {
  required_version = ">= 1.6"
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.21"
    }
  }
}

provider "vultr" {} # reads VULTR_API_KEY

variable "region" {
  type    = string
  default = "sjc"
}

variable "plan" {
  type    = string
  default = "vx1-g-2c-8g-120s" # 2 vCPU / 8 GB, about $0.076/h
}

variable "admin_cidr" {
  description = "The only address allowed to SSH in, e.g. 203.0.113.7/32"
  type        = string
}

variable "ssh_public_key" {
  type = string
}

variable "gvisor_release" {
  type    = string
  default = "20261012.0"
}

variable "sandbox_image" {
  description = "node:24-alpine, pinned by digest (same image as CI)"
  type        = string
  default     = "node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85"
}

variable "firecracker_release" {
  type    = string
  default = "v1.17.0"
}

variable "guest_kernel" {
  description = "Firecracker's CI build of Linux 6.1, pinned by path and sha256"
  type = object({
    key    = string
    sha256 = string
  })
  default = {
    key    = "firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.1.176"
    sha256 = "b9a22e694939105a63b074e2de127573ab84e4d4a0b235ae4ef92bbfc5b0fcc7"
  }
}

locals {
  debian_13 = 2625
  labels    = "redhanded"
}

resource "vultr_ssh_key" "admin" {
  name    = "redhanded-admin"
  ssh_key = var.ssh_public_key
}

resource "vultr_firewall_group" "web" {
  description = "redhanded: web open, ssh from admin only"
}

resource "vultr_firewall_rule" "ssh" {
  firewall_group_id = vultr_firewall_group.web.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = split("/", var.admin_cidr)[0]
  subnet_size       = tonumber(split("/", var.admin_cidr)[1])
  port              = "22"
  notes             = "admin ssh"
}

resource "vultr_firewall_rule" "web_v4" {
  for_each          = toset(["80", "443"])
  firewall_group_id = vultr_firewall_group.web.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = each.value
}

resource "vultr_firewall_rule" "web_v6" {
  for_each          = toset(["80", "443"])
  firewall_group_id = vultr_firewall_group.web.id
  protocol          = "tcp"
  ip_type           = "v6"
  subnet            = "::"
  subnet_size       = 0
  port              = each.value
}

resource "vultr_instance" "demo" {
  region            = var.region
  plan              = var.plan
  os_id             = local.debian_13
  label             = "redhanded-demo"
  hostname          = "redhanded-demo"
  tags              = [local.labels]
  enable_ipv6       = true
  backups           = "disabled"
  ddos_protection   = false
  activation_email  = false
  ssh_key_ids       = [vultr_ssh_key.admin.id]
  firewall_group_id = vultr_firewall_group.web.id
  user_data = templatefile("${path.module}/cloud-init.yaml", {
    gvisor_release = var.gvisor_release
    sandbox_image  = var.sandbox_image
    fc_release     = var.firecracker_release
    kernel_key     = var.guest_kernel.key
    kernel_sha256  = var.guest_kernel.sha256
  })
}

output "ip" {
  value = vultr_instance.demo.main_ip
}

output "url" {
  # sslip.io resolves a-b-c-d.sslip.io to a.b.c.d, so Caddy can get a real certificate without a domain.
  value = "https://${replace(vultr_instance.demo.main_ip, ".", "-")}.sslip.io"
}

output "hourly_cost_note" {
  value = "vx1-g-2c-8g-120s is about $0.076/h; run terraform destroy when judging ends"
}

output "plan" {
  value = var.plan
}

output "region" {
  value = var.region
}
