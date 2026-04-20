# Terraform Deploy

This is an example terraform deployment that uses the built terraform module for
development / testing purposes. To deploy the module:

```bash
make build
cd terraform_deploy
terraform init
terraform apply
```

You can also create a `terraform.tfvars` file to avoid having to set the
required variables on the command line:

```bash
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars  # Add your personal configuration here
```
