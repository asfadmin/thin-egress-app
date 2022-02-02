import boto3

client = boto3.client('s3')
s3 = boto3.resource('s3')

buckets = client.list_buckets()

for bucket in buckets['Buckets']:
    if bucket['Name'].startswith('tea'):
        print("Cleaning up bucket:" + bucket['Name'])
        s3_bucket = s3.Bucket(bucket['Name'])
        s3_bucket.objects.all().delete()
        s3_bucket.delete()
