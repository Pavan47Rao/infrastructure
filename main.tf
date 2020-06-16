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
        security_groups = ["${aws_security_group.application.id}"]
    } 
    tags = {
      Name = "database"
    }
}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket" "webappBucket" {
  bucket = "webapp.pavan.rao"
  acl    = "private"

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
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

data "aws_subnet_ids" "list" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id
}

resource "aws_db_subnet_group" "subnet_group_for_rds_instance" {
  name       = "subnet_group_for_rds_instance"
  subnet_ids = ["${element(tolist(data.aws_subnet_ids.list.ids), 0)}", "${element(tolist(data.aws_subnet_ids.list.ids), 1)}", "${element(tolist(data.aws_subnet_ids.list.ids), 2)}"]

  tags = {
    Name = "subnet_group_for_rds_instance"
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0bb068f62030afadf"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.application.id]
  disable_api_termination = false
  instance_initiated_shutdown_behavior = "stop"
  subnet_id   = aws_subnet.subnet1.id
  
  root_block_device {
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name = "HelloWorld"
  }
}