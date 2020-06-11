# Infrastructure as code using Terraform

Follow below steps in order to use the AWS Terraform to create a scalable cloud application stack on AWS

1. Select the desired AWS profile in which infrastructure needs to be created using
`export AWS_PROFILE={profile_name}`

2. Prepare a plan which contains all resources: VPC, Subnets, Internet Gateway and Route Table using
`terraform plan`

3. When prompted for 'enter a value' for each of the above resources, enter the following values:

| Key | Value |
| :---  | :---  |
| var.awsRegion | aws-east-1 |
| var.routeTableCIDR | 0.0.0.0/0 |
| var.subnet1AZ | us-east-1c |
| var.subnet1CIDR | 10.0.1.0/24 |
| var.subnet2AZ | us-east-1f |
| var.subnet2CIDR | 10.0.2.0/24 |
| var.subnet3AZ | us-east-1a |
| var.subnet3CIDR | 10.0.3.0/24 |
| var.vpcCIDR | 10.0.0.0/16 |
| var.internetGatewayTagName | gateway_for_csye6225_demo_vpc |
| var.routeTableTagName | route_table_for_3_subnets |
| var.subnet1TagName | subnet1 |
| subnet2TagName | subnet2 |
| subnet3TagName | subnet3 |
| vpcTagName | csye6225_demo_vpc |

If not prompted, default values has to be provided in vars.tf

3. Apply the resources on to the infrastructure using
`terraform apply`