# CSPM with AWS

## IOAs to Highlight

EC2	Critical	EC2 security group modified to allow ingress from the public internet
EC2	Critical	Data Exfiltration from EC2 Instance
ECR	Critical	ECR repository policy modified to allow public access
IAM	Critical	IAM role assume role policy modified to allow public access
IAM	Critical	Inline administrator policy (*:*) applied to IAM principal (user, role, group)
Lambda	Critical	Lambda function policy modified to allow public access
Lambda	Critical	Lambda layer version policy modified to allow public access
S3	Critical	S3 bucket made public through ACL
S3	Critical	S3 bucket made public through policy
EC2	High	EBS snapshot modified to share publicly
RDS	High	RDS database snapshot modified to share publicly
CloudTrail	High	CloudTrail logging disabled
GuardDuty	High	GuardDuty monitoring disabled
Medium	S3 bucket access logging disabled

## Story Board
Imagine an IAM admin keys are exposed, comprimised and exploited by an attacker

### Phase 1 - Exploit a Leak
- Inline administrator policy (*:*) applied to IAM role
- Adminstrator role assume role policy modified to allow public access
- Attacker assumes the compromised role

### Phase 2 - Reduce Visibility
- CloudTrail logging disabled so defenders have a difficult time trying to trace the malicious activity.
- GuardDuty monitoring disabled so alerts will not be thrown for future malicious activity.
- VPC flow logs disabled to avoid any logging and stay under the radar, while making it difficult for defenders to track them.
- S3 Bucket access logging disabled making it difficult for a defender to identify what activity was performed within the S3 bucket.

### Phase 3 - Mass Exposure
- EC2 security group modified to allow ingress from the public internet
- ECR repository policy modified to allow public access
- Lambda function policy modified to allow public access
- EBS snapshot modified to share publicly
- RDS database snapshot modified to share publicly
- S3 bucket made public through policy

### Phase 4 - The Steal
- Data Exfiltration from EC2 Instance