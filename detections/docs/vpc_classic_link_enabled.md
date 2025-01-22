## Overview

Detect when a Virtual Private Cloud (VPC) had the ClassicLink feature enabled. ClassicLink is a legacy feature that connects EC2-Classic instances to VPC resources but bypasses modern networking controls, increasing security and operational risks. Monitoring these configurations ensures alignment with modern VPC networking practices and reduces technical debt.

**References**:
- [ClassicLink](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-classiclink.html)
- [AWS CLI Command: enable-vpc-classic-link](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/enable-vpc-classic-link.html)
