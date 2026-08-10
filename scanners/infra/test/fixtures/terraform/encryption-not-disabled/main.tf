# I033 negative: encryption explicitly enabled, or the attribute simply
# absent (absence must never be flagged).
resource "aws_db_instance" "encrypted_db" {
  identifier        = "fixture-db"
  engine            = "postgres"
  storage_encrypted = true
}

resource "aws_ebs_volume" "encrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
}

resource "aws_dynamodb_table" "default_sse" {
  name         = "fixture-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
