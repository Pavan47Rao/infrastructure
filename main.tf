provider "aws" {
    region = var.awsRegion
}

resource "aws_vpc" "csye6225_demo_vpc" {
    cidr_block = var.vpcCIDR
    enable_dns_hostnames = true
    enable_dns_support = true
    enable_classiclink_dns_support = true
    tags = {
        Name = var.vpcTagName
    }
}

resource "aws_subnet" "subnet1" {
    cidr_block = var.subnet1CIDR
    vpc_id = aws_vpc.csye6225_demo_vpc.id
    availability_zone = var.subnet1AZ
    map_public_ip_on_launch = true
    tags = {
        Name = var.subnet1TagName
    }
}

resource "aws_subnet" "subnet2" {
    cidr_block = var.subnet2CIDR
    vpc_id = aws_vpc.csye6225_demo_vpc.id
    availability_zone = var.subnet2AZ
    map_public_ip_on_launch = true
    tags = {
        Name = var.subnet2TagName
    }
}
resource "aws_subnet" "subnet3" {
    cidr_block = var.subnet3CIDR
    vpc_id = aws_vpc.csye6225_demo_vpc.id
    availability_zone = var.subnet3AZ
    map_public_ip_on_launch = true
    tags = {
        Name = var.subnet3TagName
    }
}

resource "aws_internet_gateway" "gateway_for_csye6225_demo_vpc" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id

  tags = {
    Name = var.internetGatewayTagName
  }
}

resource "aws_route_table" "route_table_for_3_subnets" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id

  route {
    cidr_block = var.routeTableCIDR
    gateway_id = aws_internet_gateway.gateway_for_csye6225_demo_vpc.id
  }

  tags = {
    Name = var.routeTableTagName
  }
}

resource "aws_route_table_association" "association_for_subnet1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_route_table_association" "association_for_subnet2" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_route_table_association" "association_for_subnet3" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "Security group for EC2 instance"
  vpc_id      = aws_vpc.csye6225_demo_vpc.id

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "react"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "node"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "react"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "node"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application"
  }
}

resource "aws_security_group" "database" {
    name = "database_security_group"
    vpc_id = aws_vpc.csye6225_demo_vpc.id
    description = "Allow incoming database connections."

    ingress {
        from_port = 3306
        to_port = 3306
        protocol = "tcp"
        security_groups = [aws_security_group.application.id]
    } 
    tags = {
      Name = "database"
    }
}

resource "aws_s3_bucket" "webappBucket" {
  bucket = "webappp.pavan.rao"
  acl    = "private"
  force_destroy = true
  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      "rule"      = "log" 
      "autoclean" = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET"]
    allowed_origins = ["*"]
  }
}

data "aws_subnet_ids" "list" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id
}

resource "aws_db_subnet_group" "subnet_group_for_rds_instance" {
  name       = "subnet_group_for_rds_instance"
  subnet_ids = ["${element(tolist(data.aws_subnet_ids.list.ids), 0)}", "${element(tolist(data.aws_subnet_ids.list.ids), 1)}"]

  tags = {
    Name = "subnet_group_for_rds_instance"
  }
}

resource "aws_db_instance" "csye6225" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "csye6225"
  username             = var.rdsUserName
  password             = var.rdsPassword
  parameter_group_name = "default.mysql5.7"
  multi_az                  = false
  identifier                = "csye6225-su2020"
  db_subnet_group_name      = aws_db_subnet_group.subnet_group_for_rds_instance.name
  publicly_accessible       = false
  vpc_security_group_ids = [aws_security_group.database.id]
  final_snapshot_identifier = "dbinstance1-final-snapshot"
  skip_final_snapshot       = "true"
}

resource "aws_dynamodb_table" "csye6225" {
  name             = "csye6225"
  hash_key         = "id"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  
  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "EC2 s3 access policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}/*"
            ]
        }
    ]
}
  EOF
}

resource "aws_iam_role" "EC2_CSYE6225" {
  name               = "EC2-CSYE6225"
  path               = "/system/"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
}
  EOF
  tags = {
    role = "ec2-access"
  }
}

resource "aws_iam_role_policy_attachment" "EC2-CSYE6225_WebAppS3" {
  role       = aws_iam_role.EC2_CSYE6225.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}

resource "aws_iam_policy" "circleci_s3_policy" {
  name        = "CircleCI-Upload-To-S3"
  description = "CircleCI-Upload-To-S3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.code_deploy_s3_bucket}",
                "arn:aws:s3:::${var.code_deploy_s3_bucket}/*"
            ]
        }
    ]
}
  EOF
}

resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_iam_policy" "circleci_code_deploy_policy" {
  name        = "CircleCI-Code-Deploy"
  description = "CircleCI-Code-Deploy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.awsRegion}:${var.accountId}:application:${aws_codedeploy_app.csye6225-webapp.name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.awsRegion}:${var.accountId}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.awsRegion}:${var.accountId}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.awsRegion}:${var.accountId}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
  EOF
}

resource "aws_iam_policy" "circleci-ec2-ami" {
  name        = "circleci-ec2-ami"
  description = "circleci-ec2-ami"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
  EOF
}

resource "aws_iam_user_policy_attachment" "circle_ci_upload_to_s3_attach" {
  user       = "cicd"
  policy_arn = aws_iam_policy.circleci_s3_policy.arn
}

resource "aws_iam_user_policy_attachment" "circle_ci_code_deploy_attach" {
  user       = "cicd"
  policy_arn = aws_iam_policy.circleci_code_deploy_policy.arn
}

resource "aws_iam_user_policy_attachment" "circle_ci_ec2_ami_attach" {
  user       = "cicd"
  policy_arn = aws_iam_policy.circleci-ec2-ami.arn
}

resource "aws_iam_policy" "ec2_s3_policy" {
  name        = "CodeDeploy-EC2-S3"
  description = "CodeDeploy-EC2-S3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:Put*",
                "s3:Delete*",
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.code_deploy_s3_bucket}",
                "arn:aws:s3:::${var.code_deploy_s3_bucket}/*",
                "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}",
                "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}/*"
            ]
        }
    ]
}
  EOF
}

resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name               = "CodeDeployEC2ServiceRole"
  path               = "/system/"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
}
  EOF
  tags = {
    role = "ec2-access"
  }
}

resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_ec2_s3_policy" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.ec2_s3_policy.arn
}

resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"
  path = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  tags = {
    Name = "CodeDeployServiceRole"
  }
}

resource "aws_iam_role_policy_attachment" "CodeDeployServiceRole_policy_attach" {
  role       = aws_iam_role.CodeDeployServiceRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

resource "aws_iam_instance_profile" "s3_profile" {
  name = "s3_profile_for_webapp"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

resource "aws_instance" "web" {
  ami           = var.ami
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.application.id]
  disable_api_termination = false
  instance_initiated_shutdown_behavior = "stop"
  subnet_id   = aws_subnet.subnet1.id
  key_name = var.keyPair
  iam_instance_profile = aws_iam_instance_profile.s3_profile.name
  
  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name = "Web App Instance"
  }

  user_data = <<-EOF
                #!/bin/bash
                sudo touch data.txt
                sudo echo APPLICATION_ENV=prod >> data.txt
                sudo echo RDS_DATABASE_NAME=${aws_db_instance.csye6225.name} >> data.txt
                sudo echo RDS_USERNAME=${aws_db_instance.csye6225.username} >> data.txt
                sudo echo RDS_PASSWORD=${aws_db_instance.csye6225.password} >> data.txt
                sudo echo RDS_HOSTNAME=${aws_db_instance.csye6225.address} >> data.txt
                sudo echo S3_BUCKET_NAME=${aws_s3_bucket.webappBucket.bucket} >> data.txt
                
  EOF
}

resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = aws_codedeploy_app.csye6225-webapp.name
  deployment_group_name = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn      = aws_iam_role.CodeDeployServiceRole.arn

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "Web App Instance"
    }
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  alarm_configuration {
    alarms  = ["my-alarm-name"]
    enabled = true
  }
}
