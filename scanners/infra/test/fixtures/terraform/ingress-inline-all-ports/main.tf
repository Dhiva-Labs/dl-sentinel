# I030 positive: all ports/protocols open to the world -> high severity.
resource "aws_security_group" "all_ports_open" {
  name        = "all-ports-open-fixture"
  description = "Fixture: all ports and protocols open to the world."

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
