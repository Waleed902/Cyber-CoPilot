"""
S3 / MinIO Client Tool for exploring cloud buckets.
"""

from src.sdk.tool import function_tool

@function_tool()
def s3_bucket_explorer(endpoint_url: str, access_key: str = "", secret_key: str = "", action: str = "list_buckets", target_bucket: str = "", target_key: str = "", region: str = "us-east-1") -> str:
    """
    Interact with an S3-compatible service (AWS S3, MinIO, LocalStack) to interact with buckets and files.
    This properly handles AWS Signature V4 authentication which raw HTTP requests fail to do.

    Args:
        endpoint_url: The full base URL to the S3 service (e.g., 'http://10.129.1.160:54321/'). Use empty string '' for default AWS.
        access_key: AWS Access Key ID / MinIO Username (leave empty for anonymous access).
        secret_key: AWS Secret Access Key / MinIO Password.
        action: The operation to perform: 'list_buckets', 'list_objects', 'get_object'.
        target_bucket: The name of the bucket (required for 'list_objects' and 'get_object').
        target_key: The specific file/key to download (required for 'get_object').
        region: The AWS region.

    Returns:
        JSON formatted results of the S3 operation.
    """
    try:
        import boto3
        import botocore
        from botocore.exceptions import ClientError
        from botocore.client import Config
    except ImportError:
        return "Error: boto3 is not installed. Please run: pip install boto3"

    out = [f"=== S3 Explorer: {action} ==="]
    
    # Configure the client
    kwargs = {}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    
    if access_key and secret_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key
    else:
        # Anonymous access configuration
        kwargs["config"] = Config(signature_version=botocore.UNSIGNED)

    kwargs["region_name"] = region

    try:
        # We explicitly use path-style addressing since MinIO defaults to it frequently on IPs
        kwargs["config"] = Config(s3={'addressing_style': 'path'}, signature_version=botocore.UNSIGNED if not access_key else 's3v4')
        s3 = boto3.client('s3', **kwargs)

        if action == "list_buckets":
            response = s3.list_buckets()
            buckets = [b['Name'] for b in response.get('Buckets', [])]
            out.append(f"[+] Found {len(buckets)} Buckets:")
            for b in buckets:
                out.append(f"  - {b}")

        elif action == "list_objects":
            if not target_bucket:
                return "Error: target_bucket must be specified for list_objects action."
            
            response = s3.list_objects_v2(Bucket=target_bucket)
            if 'Contents' in response:
                out.append(f"[+] Found {len(response['Contents'])} objects in '{target_bucket}':")
                for obj in response['Contents']:
                    out.append(f"  - {obj['Key']} (Size: {obj['Size']} bytes)")
            else:
                out.append(f"[-] Bucket '{target_bucket}' is empty or objects are hidden.")

        elif action == "get_object":
            if not target_bucket or not target_key:
                return "Error: target_bucket and target_key must be specified for get_object action."
            
            response = s3.get_object(Bucket=target_bucket, Key=target_key)
            body = response['Body'].read()
            
            # If it's a small text-based file, display it. Otherwise just show success/size.
            size = len(body)
            out.append(f"[+] Successfully downloaded '{target_key}' from '{target_bucket}' (Size: {size} bytes).")
            
            try:
                text_content = body.decode('utf-8')
                if len(text_content) < 10000:
                    out.append("\n--- FILE CONTENT ---")
                    out.append(text_content)
                    out.append("--------------------")
                else:
                    out.append("\n[File is mostly text but too large to display directly (>10KB). Saved in memory.]")
            except UnicodeDecodeError:
                out.append("\n[File appears to be binary. Content not displayed.]")

        else:
            return f"Error: Unknown action '{action}'"

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        out.append(f"[-] S3 ClientError ({error_code}): {error_msg}")
    except Exception as e:
        out.append(f"[-] Unexpected Error: {str(e)}")

    return "\n".join(out)
