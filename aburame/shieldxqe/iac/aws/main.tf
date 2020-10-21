provider "aws" {
    region = "us-west-1"
}

resource "aws_instance" "Juan-Workloads" {
    ami = "ami-05655c267c89566dd"
    instance_type = "t3.micro"

    tags = {
        Name = "Juan-Test-WL1"
        Owner = "juan@shieldx.com"
    }
}

