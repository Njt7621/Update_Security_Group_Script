import boto3
import requests

'''
Acessing EC2/RDS instances in certain AWS environments requires you to add your public IP   
address to a security group, it�s a pain if your IP address changes or you're in a different location. 
It would be great if we could have a script that intakes a security group id we define, and 
another input for our public ip address. The script will then add the ip to the security group
which will then give us access to a certain resource with the click of a button instead of having
to log into the AWS console and navigate to different screens to add the IP.
'''

#Create EC2 client
client = boto3.client('ec2')

#Create an EC2 resource representing an SecurityGroup
ec2 = boto3.resource('ec2')
security_group = ec2.SecurityGroup('id')

#Url that gets access to Users Ip Address
AMAZON_IP_ENDPOINT = 'http://checkip.amazonaws.com/'



#Get the users public Ip address
def get_public_ip():
   response = requests.get(AMAZON_IP_ENDPOINT)
   return response.text
   
   
#Get IP address from existing entry
def get_security_ip(groupid):
    # Get security group info
    security_group = ec2.SecurityGroup(groupid)
    ip_stage = security_group.ip_permissions
    # try to get ip if exists
    ip = ''
    try:
        for item in ip_stage:
            print(item)
            for item2 in item['IpRanges']:
                #print(item2['CidrIp'])
                ip = item2['CidrIp']

    except:
        print('No Entry in Security Group')

    return ip
           

# Delete security group       
def delete_security_group(GroupId, CidrIp):
    response = security_group.revoke_ingress(
        GroupId = GroupId,
        IpPermissions=[
            {
                'FromPort': 1,
                'IpProtocol': 'tcp',
                'IpRanges': [
                    {
                        'CidrIp': CidrIp
                    },
                ],
                'ToPort': 65535
            },
        ],
    )
    
    print(response)
        
        
#Add an ingress rule to a security group
def authorize_security_group_ingress(GroupId, CidrIp):
    response = client.authorize_security_group_ingress(
        GroupId= GroupId,
        IpPermissions=[
            {
                'FromPort': 1,
                'IpProtocol': 'tcp',
                'IpRanges': [
                    {
                        'CidrIp': CidrIp
                    },
                ],
                'ToPort': 65535,
            },
        ],
    )
    
    print(response)



if __name__ == '__main__':
    user = input("Input Security GroupId ")
    print(user)
    numbers = get_public_ip() 
    print(numbers)
    publicIp = numbers.strip('\n') + '/32'
    securityIp = get_security_ip(user)
    print(securityIp)
    #delete_security_group(user, securityIp)
    rule = authorize_security_group_ingress(user, publicIp)
    
