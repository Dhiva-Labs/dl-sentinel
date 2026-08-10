# I032 negative: every credential-shaped attribute is a var. reference
# (bare or interpolated), never a literal.
resource "aws_db_instance" "example" {
  identifier = "fixture-db"
  engine     = "postgres"
  password   = var.db_password
}

provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key
  secret_key = "${var.aws_secret_key}"
}
