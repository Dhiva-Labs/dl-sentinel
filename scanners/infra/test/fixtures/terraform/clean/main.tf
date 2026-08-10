# Fully clean negative control combining every safe pattern at once.
resource "aws_security_group" "restricted" {
  name        = "clean-fixture-sg"
  description = "Ingress restricted to an internal CIDR only."

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_s3_bucket" "private_bucket" {
  bucket = "clean-fixture-bucket"
  acl    = "private"
}

resource "aws_db_instance" "encrypted_db" {
  identifier        = "clean-fixture-db"
  engine            = "postgres"
  password          = var.db_password
  storage_encrypted = true
}

provider "aws" {
  region = "us-east-1"
}
