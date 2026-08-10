# I030 positive: ipv6_cidr_blocks open to ::/0, ordinary port -> medium.
resource "aws_security_group" "ipv6_open" {
  name = "ipv6-open-fixture"

  ingress {
    from_port        = 443
    to_port           = 443
    protocol          = "tcp"
    ipv6_cidr_blocks  = ["::/0"]
  }
}
