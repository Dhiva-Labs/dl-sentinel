# I032 positive: hardcoded credentials on both a provider block and a
# resource block. access_key/secret_key use AWS's own vendor-documented
# example credential pair; password is a synthetic fixture value with an
# EXAMPLE marker (see tests/fixtures/README.md conventions).
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "example" {
  identifier = "fixture-db"
  engine     = "postgres"
  password   = "FAKEDBPASSWORDEXAMPLE999"
}
