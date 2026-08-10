# I030 positive: the newer aws_vpc_security_group_ingress_rule resource,
# which is inherently ingress-only and uses cidr_ipv4 rather than
# cidr_blocks.
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = "sg-0123456789abcdef0"
  from_port          = 22
  to_port            = 22
  ip_protocol        = "tcp"
  cidr_ipv4          = "0.0.0.0/0"
}
