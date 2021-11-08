# How to use the provider
## Encrypt a secret
Lets say you have a password `MyStr0ngp@ss!` that you would like to store in SSM

First it needs encrypting.

```
aws --region us-west-2 kms encrypt --key-id <kms key id> --plaintext MyStr0ngp@ss!
```

Take the `CiphertextBlob` from the output and create a encryptedssm_parameter resource such as in the example `main.tf` 

You will need to set the encryption key parameter to the same as the key you used to encrypt the value. Terraform will use this key to decrypt the value to check if it needs updating. This key will also be used to encrypt the parameter in SSM.

After that its a simple case of running `terraform plan` and `terraform apply`.

You end up with an encrypted value in state, source and secret store.

