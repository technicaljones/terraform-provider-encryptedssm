# Terraform Provider encryptedssm


## Build provider

Run the following command to build the provider

```shell
$ go build -o terraform-provider-encryptedssm
```
## Test sample configuration

First, build and install the provider.

```shell
$ make install
```

Then, navigate to the `examples` directory. 

```shell
$ cd examples
```

Run the following command to initialize the workspace and apply the sample configuration.

```shell
$ terraform init && terraform apply
```

## What is this provider for?
tl;dr deploying secrets from terraform without security compromises 
It is a modification of the aws_ssm_parameter resouce from the official AWS provider however instead of taking plaintext
values it takes a pre encrypted value which allows storage of sensitive values in source and state.
This provider has the following resource:

`encryptedssm_parameter`

The folllowing standard parameters are available:
- `name`
- `description`
- `tier`
- `type`
- `overwrite`
- `allowed_pattern`
and are documented on the official AWS provider site - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter

This provider impliments the following additional parameters:
- `encrypted_value`
- `encryption_key`

To use the resource see the readme in the examples folder.
