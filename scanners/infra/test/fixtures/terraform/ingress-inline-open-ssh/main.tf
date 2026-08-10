# I030 positive: SSH open to the world -> high severity.
resource "aws_security_group" "ssh_open" {
  name        = "ssh-open-fixture"
  description = "Fixture: SSH open to the world."

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
