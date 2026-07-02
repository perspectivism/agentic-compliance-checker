# Fixture: insecure_terraform_app
# Intended GAP evidence for AC-3 (public admin access), AC-6 (wildcard IAM),
# SC-7 (permissive ingress, no segmentation), SC-28 (no encryption at rest),
# SC-8 (plain HTTP).

resource "aws_security_group" "open_ssh" {
  name = "open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "example-insecure-data"
  # No server-side encryption configuration. No public access block.
}

resource "aws_iam_policy" "admin" {
  name = "wide-open"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
