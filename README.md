# aws-ocsp
A fully-serverless x.509 OCSP responder using AWS Lambda, AWS S3, and AWS DynamoDB.

## Usage

### Install serverless framework
```bash
npm install -g serverless
```

### Download this project and required plugins
```bash
serverless install --url https://github.com/heri16/aws-ocsp --name ocsp
cd ocsp
npm install --only=dev
```

### Edit custom section of serverless.yml
```bash
nano ./serverless.yml
```
```yaml
custom:
  customDomain:
    domainName: pki.lmu.co.id
  s3_bucket: lmu-pki
  s3_key_base: certs/
```

### Request a free ACM Certificate for your custom domainName (if not yet created)
http://docs.aws.amazon.com/acm/latest/userguide/gs.html

### Create the bucket on Amazon S3 (if not yet created)
https://docs.aws.amazon.com/AmazonS3/latest/user-guide/create-bucket.html

### Add relevant files to config folder (Adjust environment vars accordingly)
```bash
ls ./config
```
```yaml
functions:
  respond:
    environment:
      # OCSP_COUNT should denote the total number of OCSP responders (in-case of serving intermediate-CAs)
      OCSP_COUNT: '2'
      # PFX files should contain ocsp signer's privKey (and all related certificates in the chain)
      OCSP_PFX_1: 'config/ocsp1.pfx'
      OCSP_PFX_PASS_1: 'pass_for_ocsp1'
      # 2nd OCSP Responder/Signer
      OCSP_PFX_2: 'config/ocsp2.pfx'
      OCSP_PFX_PASS_2: 'pass_for_ocsp2'
  bucket:
    environment:
      # One or many Root certificates in PEM-format to validate the certificates before being registered into OCSP
      TRUST_ROOTS: 'config/root_bundle.pem'
```

### Deploy project to AWS
```bash
serverless create_domain
pipenv run serverless deploy --stage=prod
serverless s3deploy
```

### Check aws credentials if you have trouble deploying
```bash
nano ~/.aws/credentials

aws iam attach-user-policy --user-name <your_username> --policy-arn arn:aws:iam::aws:policy/AWSLambdaFullAccess
aws iam attach-user-policy --user-name <your_username> --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccesswithDataPipeline
aws iam attach-user-policy --user-name <your_username> --policy-arn arn:aws:iam::aws:policy/SystemAdministrator
aws iam attach-user-policy --user-name <your_username> --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
```
