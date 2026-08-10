# I033 positive: encryption explicitly disabled three different ways.
resource "aws_db_instance" "no_storage_encryption" {
  identifier        = "fixture-db"
  engine            = "postgres"
  storage_encrypted = false
}

resource "aws_ebs_volume" "no_encryption" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

resource "aws_dynamodb_table" "no_sse" {
  name         = "fixture-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = false
  }
}
