import boto3

# Yandex Object Storage Access
cos = boto3.client(
    's3',
    aws_access_key_id = 'YCAJEq23MSLvRBTVBkQ9-f4kS',
    aws_secret_access_key = 'YCP51sph009N24z5-1fSyvoITeekQAlJbWTJgS31',
    region_name = 'ru-central1',
    endpoint_url = 'https://storage.yandexcloud.net'
)

# # Load file in the bucket
# def upload_file(bucket_name, object_name):
#     os.upload_file(object_name, bucket_name, object_name)
#
# # Delete file from bucket
# def delete_file(bucket_name, object_name):
#     os.delete_object(Bucket=bucket_name, Key=object_name)
#
# Return from Bucket Url of the requested object
def get_obj_url(bucket_name, id):
    obj_url = cos.generate_presigned_url(ClientMethod='get_object', Params = {'Bucket': bucket_name, 'Key': id})
    return obj_url
#
# image_url = get_obj_url('xraylabbucket', 'test/images/motoroller.png')
# print("Image: ", image_url)
# mask_url = get_obj_url('xraylabbucket', 'test/masks/motoroller.png')
# print("Mask: ", mask_url)
