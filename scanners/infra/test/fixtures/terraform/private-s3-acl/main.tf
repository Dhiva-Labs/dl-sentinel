# I031 negative: a private ACL.
resource "aws_s3_bucket" "private_bucket" {
  bucket = "example-fixture-private-bucket"
  acl    = "private"
}
