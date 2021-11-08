terraform {
  required_providers {
    encryptedssm = {
      versions = ["0.1"]
      source = "hashicorp.com/providers/encryptedssm"
    }
  }
}

provider "encryptedssm" {
  region = "us-west-2"
}

resource "encryptedssm_parameter" "test" {
  name            = "/path/to/secret"
  type            = "SecureString"
  encryption_key  = "kms key id"
  encrypted_value = "cipher text blob"
}
