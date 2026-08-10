resource "aws_security_group" "broken {
  ingress {
    from_port = 22
    to_port =
    protocol "tcp"
    cidr_blocks = ["0.0.0.0/0"

}
