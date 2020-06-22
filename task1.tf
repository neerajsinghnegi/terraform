# authentication
provider "aws" {
  region = "ap-south-1"
  profile = "neeraj"
}

#Generate a key
resource "tls_private_key" "keyGenerate" {
    algorithm = "RSA"
}

# create key-pairs
resource "aws_key_pair" "key-pairs" {
depends_on = [
	tls_private_key.keyGenerate
    ]
  key_name   = "tf-key"
  public_key = tls_private_key.keyGenerate.public_key_openssh
}

# saving key in local system
resource "local_file" "keySave" {
    depends_on = [
	tls_private_key.keyGenerate
    ]
    content = tls_private_key.keyGenerate.private_key_pem
    filename = "tf-key.pem"
}

# create security-groups
resource "aws_security_group" "webserver" {
  name        = "webserver"
  description = "Allow webserver inbound traffic"
  vpc_id      = "vpc-348a975c"

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
	cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
	cidr_blocks = ["0.0.0.0/0"]
  }
   egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "webserver_sg"
  }
}

# launch ec2 instance and configure apache-webserver
resource "aws_instance" "tf_instance" {
depends_on = [
    aws_security_group.webserver,aws_key_pair.key-pairs
  ]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = aws_key_pair.key-pairs.key_name
  security_groups = [ "webserver" ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.keyGenerate.private_key_pem
    host     = aws_instance.tf_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd"
    ]
  }

  tags = {
    Name = "tf_os"
  }
}

# create EBS volume
resource "aws_ebs_volume" "tf_ebs_vol" {
depends_on = [
    aws_instance.tf_instance,
  ]
  availability_zone = aws_instance.tf_instance.availability_zone
  size              = 1
  tags = {
    Name = "tf_ebs_vol_1gb"
  }
}

# mount EBS volume to ec2 instance
resource "aws_volume_attachment" "tf_ebs_attach" {
depends_on = [
    aws_ebs_volume.tf_ebs_vol,
  ]
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.tf_ebs_vol.id
  instance_id = aws_instance.tf_instance.id
  force_detach = true
}

# ebs mount /var/www/html (webserver)
resource "null_resource" "mount-web-file"  {
depends_on = [
    aws_volume_attachment.tf_ebs_attach,
  ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.keyGenerate.private_key_pem
    host     = aws_instance.tf_instance.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/neerajsinghnegi/testingdata.git /var/www/html/",
	  "sudo setenforce 0"
    ]
  }
}

# create s3 bucket
resource "aws_s3_bucket" "s3-bucket"{
depends_on = [
	null_resource.mount-web-file,
	]
  bucket = "tf-neeraj-bucket"
  acl = "private"
  force_destroy = true
      tags = {
        Name = "s3-web-bucket"
  }
}

locals {
    s3_origin_id = "tf-neeraj-bucket"
}

# copy static content to s3-bucket
resource "null_resource" "s3-copy-files" {
    depends_on = [
        aws_s3_bucket.s3-bucket
    ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.keyGenerate.private_key_pem
    host     = aws_instance.tf_instance.public_ip
  }
 
   provisioner "remote-exec" {
    inline = [
	  "curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip",
	  "sudo yum install unzip -y",
	  "unzip awscliv2.zip",
	  "chmod +x /home/ec2-user/./aws",
	  "sudo ./aws/install -i /usr/local/aws-cli",
	  "AWS_ACCESS_KEY_ID=AKIA4ZUBJ6FV4364MZNO AWS_SECRET_ACCESS_KEY=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 aws s3 cp /var/www/html s3://tf-neeraj-bucket/ --recursive --include '*.png'"
    ]
  }
} 

# create cloudfront origin access identity
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
depends_on = [
	null_resource.s3-copy-files,
	]
  comment = "origin access identity"
}

# create cloudfront distribution 
resource "aws_cloudfront_distribution" "s3-distribution" {
      depends_on = [
          aws_cloudfront_origin_access_identity.origin_access_identity
      ]
      origin {
          domain_name = aws_s3_bucket.s3-bucket.bucket_regional_domain_name
          origin_id   = local.s3_origin_id

		s3_origin_config {
			origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
			}
		}	

      enabled             = true
      is_ipv6_enabled     = true

      default_cache_behavior {
          allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
          cached_methods   = ["GET", "HEAD"]
          target_origin_id = local.s3_origin_id

          forwarded_values {
              query_string = false

              cookies {
                  forward = "none"
              }
          }

          viewer_protocol_policy = "allow-all"
          min_ttl                = 0
          default_ttl            = 3600
          max_ttl                = 86400
      }

      wait_for_deployment = false
      restrictions {
          geo_restriction {
              restriction_type = "none"
			}
		}

      tags = {
          Environment = "Testing"
      }

      viewer_certificate {
          cloudfront_default_certificate = true
      }
  }

# create s3 iam policy document  
data "aws_iam_policy_document" "s3Policy" {
      statement {
          actions   = ["s3:GetObject"]
          resources = ["${aws_s3_bucket.s3-bucket.arn}/*"]

          principals {
              type        = "AWS"
              identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
          }
      }

      statement {
          actions   = ["s3:ListBucket"]
          resources = ["${aws_s3_bucket.s3-bucket.arn}"]

          principals {
              type        = "AWS"
              identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
          }
      }
  }

#create s3 bucket policy  
resource "aws_s3_bucket_policy" "bucketReadPolicy" {
    depends_on = [
        aws_s3_bucket.s3-bucket
    ]
      bucket = aws_s3_bucket.s3-bucket.id
      policy = data.aws_iam_policy_document.s3Policy.json
  }

# update url with cloudfront-distribution
resource "null_resource" "update-url" {
      depends_on = [
          aws_cloudfront_distribution.s3-distribution,
      ]

      connection {
          type     = "ssh"
          user     = "ec2-user"
          private_key = tls_private_key.keyGenerate.private_key_pem
          host     = aws_instance.tf_instance.public_ip
      }

      provisioner "remote-exec" {
          inline = [
              "sudo sed -i 's|url|https://${aws_cloudfront_distribution.s3-distribution.domain_name}|g' /var/www/html/index.html"
          ]
      }
  }
  
  output "Website-ip" {
      value = aws_instance.tf_instance.public_ip
  }

# automatic website opens
resource "null_resource" "open-automatic-site" {
      depends_on = [
          null_resource.update-url
      ]
      provisioner "local-exec" {
          command = "chrome http://${aws_instance.tf_instance.public_ip}/index.html"
      }
  } 

