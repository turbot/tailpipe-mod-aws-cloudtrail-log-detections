## Overview

Detect when an Amazon Simple Email Service (SES) identity had feedback forwarding disabled. Feedback forwarding ensures that bounce and complaint notifications are sent to the email sender, which is critical for monitoring email deliverability and managing sender reputation. Disabling this feature may result in undetected email delivery issues or compromised email sending practices.

**References**:
- [Monitoring Using Amazon SES Notifications](https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html)
- [Best Practices for Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/best-practices.html)
- [AWS CLI Command: update-receipt-rule](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ses/update-receipt-rule.html)
