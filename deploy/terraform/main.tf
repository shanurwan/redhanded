# One Vultr VM runs the demo site, the scan worker, gVisor and the sinkhole.
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
  default = "lax"
}

variable "plan" {
  type    = string
  default = "vc2-2c-4gb" # 2 vCPU / 4 GB: big native packages need the memory
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
  value = "vc2-2c-4gb is about $0.027/h; run terraform destroy when judging ends"
}

output "plan" {
  value = var.plan
}

output "region" {
  value = var.region
}
