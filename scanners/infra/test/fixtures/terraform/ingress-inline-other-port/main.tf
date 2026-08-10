# I030 positive: an ordinary app port open to the world (not admin, not
# all-ports) -> medium severity.
resource "aws_security_group" "web_open" {
  name        = "web-open-fixture"
  description = "Fixture: a single ordinary port open to the world."

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
