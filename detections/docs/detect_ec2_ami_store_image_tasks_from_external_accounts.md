## Description

This detection identifies instances where store image tasks are initiated for Amazon Machine Images (AMIs) from external accounts. Storing AMIs from external sources can introduce untrusted or potentially malicious resources into your environment. Monitoring these tasks ensures that only vetted and secure AMIs are stored and used within your AWS environment.

## Risks

Storing AMIs from external accounts can pose significant security risks. External images may contain vulnerabilities, malware, or misconfigurations that can compromise the security of your environment. If deployed, such AMIs can expose EC2 instances to unauthorized access, data breaches, or exploitation by malicious actors.

Additionally, AMIs sourced externally may not align with your organization’s compliance or security policies, increasing the likelihood of non-compliance with regulatory or industry standards. This can lead to operational inefficiencies, legal liabilities, or reputational damage if untrusted images are used in critical workloads. 

Monitoring and validating AMI store image tasks from external accounts helps reduce the attack surface and ensures the integrity of your infrastructure.

## References

- [AWS Documentation: Exporting an Instance as a VM Using VM Import/Export](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html)
- [AWS CLI Command: create-store-image-task](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-store-image-task.html)
- [AWS Documentation: Amazon Machine Images (AMIs)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
