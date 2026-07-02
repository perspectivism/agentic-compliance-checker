# Fixture: partial_network_app
# Intended PARTIAL evidence for SC-7 (Boundary protection). The app tier's
# ingress rule references a security group (security_groups = [...]) rather
# than a CIDR range; the database tier's ingress rule allows 0.0.0.0/0
# (internet-wide/permissive CIDR ingress). docs/RUBRIC.md: SC-7 is "Partial
# if only some tiers protected" — this repo has one tier using the
# internal-only pattern and one tier that doesn't. (This file only declares
# resource attributes; it makes no claim about route tables, an internet
# gateway, or NACLs, which aren't present here.)

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app_private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  # map_public_ip_on_launch not set (provider default: false).
}

resource "aws_subnet" "db_private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.3.0/24"
}

resource "aws_db_subnet_group" "db" {
  name       = "app-db-subnet-group"
  subnet_ids = [aws_subnet.db_private.id]
}

resource "aws_security_group" "web" {
  name   = "web-tier"
  vpc_id = aws_vpc.main.id
}

# Positive SC-7 evidence: the app tier's ingress rule references the web
# tier's security group (security_groups = [...]) instead of a CIDR range.
resource "aws_security_group" "app" {
  name   = "app-tier"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}

# GAP SC-7 evidence: the database tier's ingress rule allows 0.0.0.0/0
# (internet-wide/permissive CIDR ingress) rather than a security-group
# reference — unlike the app tier above, this rule doesn't use the
# internal-only pattern.
resource "aws_security_group" "db" {
  name   = "db-tier"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
