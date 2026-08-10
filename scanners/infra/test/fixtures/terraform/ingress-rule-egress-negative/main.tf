# I030 negative: an aws_security_group_rule with type = "egress" is out of
# scope for the ingress rule, even though it is wide open.
resource "aws_security_group_rule" "all_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-0123456789abcdef0"
}
