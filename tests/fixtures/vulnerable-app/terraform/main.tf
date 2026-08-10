# Deliberately insecure fixture Terraform for DL Sentinel scanner tests.
# Never planned or applied; a pattern target only.

resource "aws_security_group" "wide_open" {
  name        = "vulnerable-app-fixture-sg"
  description = "Fixture security group with an intentionally open ingress rule."

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "vulnerable-app-fixture-bucket"
  acl    = "public-read"
}
