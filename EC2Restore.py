import json
import boto3
import logging
from os import getenv

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    backup = boto3.client('backup')
    logger = logging.getLogger()
    log_level = getenv("LOGLEVEL", "INFO")
    level = logging.getLevelName(log_level)
    logger.setLevel(level)
    logger.info('---- Start of Execution ---- ')
    logger.info('Trigger Event - Tag Change on Resource :')
    logger.info(event)

    #Init Variables
    process= False
    activation_tag_key = getenv("ACTIVATION_TAG_KEY", "Restore")
    BackupVaultTags = event['detail']['tags']
    BackupIAMRole = getenv("BACKUP_IAM_ROLE_ARN")
    
    #getting BakupVaultName from ARN
    BackupVaultName=event['resources'][0]
    BackupVaultName=BackupVaultName.split(':')
    BackupVaultName=BackupVaultName[6]

    #getting Recovery Point ID
    if activation_tag_key in BackupVaultTags.keys():
        logger.info("Activation Key exist : {}".format(activation_tag_key))
        process= True
        logger.info("BackupVault Name : {}".format(BackupVaultName))
        Recovery_Point_ID=BackupVaultTags[activation_tag_key]
        logger.info("Recovery Point ID : {}".format(Recovery_Point_ID))

        #removing the activation tag
        desc_vault=backup.describe_backup_vault(
            BackupVaultName=BackupVaultName
            )
        backup_vault_arn=desc_vault['BackupVaultArn']
        desc_vault=backup.untag_resource(
            ResourceArn=backup_vault_arn,
            TagKeyList=[activation_tag_key]
            )

    #Processing
    if process:
        #getting Recovery Point ARN
        bkp_resource_list = backup.list_recovery_points_by_backup_vault(
            BackupVaultName=BackupVaultName
            )
        for i in range(len(bkp_resource_list['RecoveryPoints'])):
            if Recovery_Point_ID in bkp_resource_list['RecoveryPoints'][i]['RecoveryPointArn']:
                RecoveryPointArn=(bkp_resource_list['RecoveryPoints'][i]['RecoveryPointArn'])
                logger.info("Recovery Point Arn : {}".format(RecoveryPointArn))
        
        #getting the Recovery Point Restore Metadata
        logger.info('Gathering Metadata from Backup')
        response=backup.get_recovery_point_restore_metadata(
            BackupVaultName=BackupVaultName,
            RecoveryPointArn=RecoveryPointArn
            )
        restore_metadata=response['RestoreMetadata']
        logger.info('Recovery Point Restore Metadata :')
        logger.info(restore_metadata)

        #editing the Metadata to suit the request parameter
        logger.info('Processing the Metadata :')
        if 't2.' in restore_metadata['InstanceType']:
            logger.info(' -- CpuOptions for T2 Instances is deleted')
            restore_metadata.pop('CpuOptions')
        #deleting SubnetId SecurityGroupsIds aws:backup:request-id
        restore_metadata.pop('SecurityGroupIds')
        restore_metadata.pop('SubnetId')
        logger.info(' -- SubnetId SecurityGroupsIds in root-level are deleted')
        restore_metadata.pop('aws:backup:request-id')
        logger.info(' -- aws:backup:request-id is deleted')
        logger.info(' -- Processing NetworkInterfaces')
        #editing the NetworkInterfaces
        network_interfaces=json.loads(restore_metadata['NetworkInterfaces'])
        restore_metadata.pop('NetworkInterfaces')
        logger.info(' -- eni count: {}'.format(len(network_interfaces)))
        multi_eni = False
        if len(network_interfaces) > 0:
            multi_eni = True
        for i in range(len(network_interfaces)):
            del network_interfaces[i]['NetworkInterfaceId']
            del network_interfaces[i]['PrivateIpAddress']
            if multi_eni:
                del network_interfaces[i]['AssociatePublicIpAddress']
            if network_interfaces[i]['SecondaryPrivateIpAddressCount'] == 0:
                del network_interfaces[i]['SecondaryPrivateIpAddressCount']
        restore_metadata['NetworkInterfaces']=json.dumps(network_interfaces)
        logger.info('Processing Result :')
        logger.info(restore_metadata)

        #Starting the Recovery Job
        logger.info('Restore Job Started ( Check job progress on AWS Backup console)')
        recovery_job=backup.start_restore_job(
            RecoveryPointArn=RecoveryPointArn,
            Metadata=restore_metadata,
            IdempotencyToken=event['id'],
            IamRoleArn=BackupIAMRole
            )
        RestoreJobId=recovery_job['RestoreJobId']
        logger.info('Restore Job id:  {}'.format(RestoreJobId))

        #getting AMI ID from the Recovery Point ARN
        ami_id = RecoveryPointArn.split('/')
        ami_id = ami_id[1]

        #getting the InstanceID of the restored instance
        instance_not_launched= True
        logger.info('Checking the launched EC2 instance with AMI-ID : {}  '.format(ami_id))  
        while instance_not_launched:
            ec2_desc = ec2.describe_instances(
                Filters=[
                        {
                            'Name' : 'instance-state-name',
                            'Values' : ['pending']
                        },
                        {
                            'Name' : 'image-id',
                            'Values' : [ami_id]
                        },
                    ],
            )
            if len(ec2_desc['Reservations']) > 0:
                instance_not_launched= False
        instance_id=ec2_desc['Reservations'][0]['Instances'][0]['InstanceId']
        logger.info(' -- EC2 Instance Id : {}  '.format(instance_id))

        #adding AMI Tags to the restored EC2 Instance except the aws:backup reserved tag
        image_desc=ec2.describe_images(
            ImageIds=[ami_id]
                )
        ami_tags=image_desc['Images'][0]['Tags']
        tag_sum=0
        logger.info('Restoring EC2 Tags:')
        for element in ami_tags:
            if (element['Key'] != 'aws:backup:source-resource'):
                tag_sum=tag_sum+1
                ec2.create_tags(
                    Resources=[instance_id],
                    Tags=[
                            {
                                'Key': element['Key'],
                                'Value' : element['Value'],
                            },
                        ],
                    )
                logger.info(' -- Tag restored : {}  '.format(element['Key']))
        logger.info('Process complete :  {} tags restored. '.format(tag_sum))
        logger.info('---- End of Execution ---- ')
    else:
        logger.info('Activation Tag not assigned')
        logger.info('---- End of Execution ---- ')
