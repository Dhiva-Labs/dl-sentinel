# I031 positive: the standalone aws_s3_bucket_acl resource.
resource "aws_s3_bucket_acl" "public" {
  bucket = "example-fixture-bucket"
  acl    = "public-read"
}
