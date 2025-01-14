## Description

This detection identifies Amazon CloudFront distribution origins that are configured to allow unrestricted public access. Origins are the source of the content served by CloudFront, and granting public access without proper security controls can expose backend systems and sensitive data to unauthorized users and malicious actors.

## Risks

Granting public access to CloudFront distribution origins can significantly compromise the security of backend systems. Without proper access restrictions, attackers could directly access the origin server, bypassing CloudFront's caching and security features. This could lead to data breaches, unauthorized modifications, or exploitation of backend vulnerabilities.

Additionally, publicly accessible origins increase the risk of abuse, such as traffic floods or unauthorized downloads of sensitive content. Properly configuring access restrictions for origins, such as using signed URLs, signed cookies, or origin access control, ensures that only authorized requests reach the origin server, enhancing security and maintaining compliance.

## References

- [Restricting Access to Origins](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-origin.html)
- [CloudFront Signed URLs and Cookies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html)
- [AWS CLI Command: update-distribution](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html)
