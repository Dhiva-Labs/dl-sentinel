# I031 positive: inline acl on aws_s3_bucket.
resource "aws_s3_bucket" "public_bucket" {
  bucket = "example-fixture-public-bucket"
  acl    = "public-read-write"
}
