import azure.functions as func
import logging
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.identity import ClientSecretCredential

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

import os
import logging
import requests
import winrm

logging.basicConfig(level=logging.INFO)

@app.function_name(name="HttpTrigger")
@app.route(route="", auth_level=func.AuthLevel.ANONYMOUS)
def HttpTrigger(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Python HTTP trigger function processed a request.')
        request_json=req.get_json()
        deployment_name=request_json['recoveryName']
        primary_resource_metadata_url = request_json['resourceMapping']['primaryResourceMetadataPath']
        recovered_metadata_url = request_json['resourceMapping']['recoveredMetadataPath']
        # source_recovery_mapping_url = request_json['resourceMapping']['sourceRecoveryMappingPath']

        # Send GET requests and print the JSON responses
        json1 = requests.get(recovered_metadata_url).json()
        logging.info(json1)

        for item in json1:
            for key, value in item.items():
                for item_data in value:
                    recovery_resource_group = item_data['groupIdentifier']
                    recovery_region = item_data['region'].replace(
                        ' ', '').lower()
                    subscription_id = item_data['cloudResourceReferenceId'].split(
                        "/")[2]
                    break

      # Send GET requests and print the JSON responses
        json2 = requests.get(primary_resource_metadata_url).json()
        logging.info(json1)

        for item in json2:
            for key, value in item.items():
                for item_data in value:
                    resource_group_name = item_data['groupIdentifier']
                    location = item_data['region'].replace(' ', '').lower()
                    # recovery_subscription_id = item_data['cloudResourceReferenceId'].split("/")[2]
                    break

        for item in json2:
            if 'RESOURCE_GROUP' in item:
                recovery_resource_group = deployment_name+"-"+item['RESOURCE_GROUP'][0]['name']
                break

        client_id = os.environ["CLIENT_ID"]
        client_secret = os.environ["CLIENT_SECRET"]
        tenant_id = os.environ["TENANT_ID"]
        
        # Create a client secret credential object
        credential = ClientSecretCredential(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id
        )

        # Create an instance of the SQL management client
        sql_client = SqlManagementClient(credential, subscription_id)

        # List all Microsoft SQL servers in the recovery resource group
        servers = sql_client.servers.list_by_resource_group(resource_group_name)
        # print(f"Listing all Microsoft SQL servers in the recovery resource group '{resource_group_name}'")

        # Iterate over each server
        for server in servers:
            if server.location==location:
                # print(f"Checking server '{server.name}' for read replicas")
                # List the read replicas for the server
                replicas = sql_client.replication_links.list_by_server(resource_group_name, server.name)
                
                # Iterate over each replica
                for replica in replicas:
                    # print(f"Checking replica '{replica.partner_server}' located in '{replica.partner_location}'")
                    # print(replica.partner_location)
                    # Check if the replica is located in the recovery region
                    if replica.partner_location.replace(' ','').lower() == recovery_region:
                        # print(f"Promoting replica '{replica.partner_server}' to become the primary server")
                        
                        # Promote the replica to become the primary server
                        sql_client.replication_links.begin_failover(
                            resource_group_name,
                            replica.partner_server,
                            replica.partner_database,
                            replica.name
                        )  
                        server_name=server.name
                        replica_name=replica.partner_server

                        # Create clients for Compute and Network management
                        compute_client = ComputeManagementClient(credential, subscription_id)
                        network_client = NetworkManagementClient(credential, subscription_id)

                        # Get all virtual machines in the resource group
                        vms = compute_client.virtual_machines.list(recovery_resource_group)

                        # Iterate over each virtual machine and get its public IP address
                        for vm in vms:
                            # Get the network interface for the VM
                            nic_id = vm.network_profile.network_interfaces[0].id
                            nic_name = nic_id.split('/')[-1]
                            nic = network_client.network_interfaces.get(recovery_resource_group, nic_name)

                            # Get the public IP address for the network interface
                            if nic.ip_configurations[0].public_ip_address:
                                public_ip_id = nic.ip_configurations[0].public_ip_address.id
                                public_ip_name = public_ip_id.split('/')[-1]
                                public_ip_address = network_client.public_ip_addresses.get(recovery_resource_group, public_ip_name)
                                
                                

                                host = str(public_ip_address.ip_address)
                                user = os.environ["USER"]
                                password = os.environ["PASSWORD"]

                                try:
                                    session = winrm.Session(host, auth=(user, password), transport='ntlm')

                                    file_path = os.environ["FILE_PATH"]

                                    cmd = f'if exist "{file_path}" (echo true) else (echo false)'
                                    result = session.run_cmd(cmd)

                                    if result.std_out.strip() == b'true':
                                        cmd = f'Get-Content -Path "{file_path}"'
                                        result = session.run_ps(cmd)
                                        file_contents = result.std_out.decode('utf-8')

                                        file_contents = file_contents.replace(server_name, replica_name)

                                        cmd = f'Set-Content -Path "{file_path}" -Value @"\n{file_contents}\n"@'
                                        session.run_ps(cmd)
                                        cmd = f'Restart-WebAppPool -Name "APPRANIX_myclouditecplatformapi.ciodev.accenture.com"'
                                        session.run_ps(cmd)

                                        print('File Updated')
                                        return func.HttpResponse(
                                            "200",
                                            status_code=200)
                                    else:
                                        print('File does not exist or access denied')
                                        logging.error(f"File does not exist or access denied")

                                except Exception as e:
                                    print(f'An error occurred: {str(e)}')
                                    return func.HttpResponse(f"Error occurred: {str(e)}\n. This HTTP triggered function executed successfully.",status_code=400)
                                
    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(f"Error occurred: {str(e)}\n. This HTTP triggered function executed successfully.",status_code=400)
    return func.HttpResponse(
                    "200",
                    status_code=200)
