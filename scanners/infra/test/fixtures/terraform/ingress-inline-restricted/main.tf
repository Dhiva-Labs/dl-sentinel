# I030 negative: ingress restricted to a private CIDR, not open to the world.
resource "aws_security_group" "restricted" {
  name        = "restricted-fixture"
  description = "Fixture: ingress restricted to an internal CIDR only."

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
