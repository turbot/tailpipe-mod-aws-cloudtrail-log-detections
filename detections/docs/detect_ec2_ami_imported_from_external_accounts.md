## Description

This detection identifies instances where Amazon Machine Images (AMIs) are imported into your AWS environment from external sources. Importing AMIs from unverified accounts or external environments can introduce security vulnerabilities or malicious configurations, putting your infrastructure at risk. Monitoring such imports ensures that only trusted and validated images are used.

## Risks

Importing AMIs from external accounts poses significant risks to the security and integrity of your environment. These images may contain unknown vulnerabilities, malicious code, or misconfigurations that could compromise your EC2 instances. Deploying untrusted AMIs can lead to unauthorized access, data breaches, or the introduction of malware into your systems.

In addition, imported AMIs may not adhere to your organization’s compliance and security policies, increasing the likelihood of non-compliance with industry standards or regulations. This could expose your infrastructure to operational risks, reduced availability, and potential exploitation by attackers leveraging backdoors or weak configurations embedded in the AMI.

## References

- [AWS Documentation: Importing a VM as an AMI](https://docs.aws.amazon.com/vm-import/latest/userguide/vmimport-image-import.html)
- [AWS CLI Command: import-image](https://docs.aws.amazon.com/cli/latest/reference/ec2/import-image.html)
- [AWS Documentation: Amazon Machine Images (AMIs)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
