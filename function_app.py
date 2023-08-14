import azure.functions as func
import logging
import os
import logging
import requests
import winrm
import re
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.identity import ClientSecretCredential

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

logging.basicConfig(level=logging.WARNING)

@app.route(route="HttpTrigger", auth_level=func.AuthLevel.ANONYMOUS)
def HttpTrigger(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.warning('Python HTTP trigger function processed a request.')
        request_json=req.get_json()
        deployment_name=request_json['recoveryName']
        primary_resource_metadata_url = request_json['resourceMapping']['primaryResourceMetadataPath']
        recovered_metadata_url = request_json['resourceMapping']['recoveredMetadataPath']
        # source_recovery_mapping_url = request_json['resourceMapping']['sourceRecoveryMappingPath']
        logging.warning(request_json)
        # Send GET requests and print the JSON responses
        json1 = requests.get(recovered_metadata_url).json()
        logging.warning(json1)

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
        logging.warning(json2)

        for item in json2:
            for key, value in item.items():
                for item_data in value:
                    resource_group_name = item_data['groupIdentifier']
                    recovery_resource_group = deployment_name+"-"+resource_group_name
                    location = item_data['region'].replace(' ', '').lower()
                    # recovery_subscription_id = item_data['cloudResourceReferenceId'].split("/")[2]
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
        # Create clients for Compute and Network management
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        # List all Microsoft SQL servers in the recovery resource group
        servers = sql_client.servers.list_by_resource_group(resource_group_name)
        logging.warning(f"Listing all Microsoft SQL servers in the recovery resource group '{resource_group_name}'")
        
        resetsql=False
        if "resetUser" in request_json:
            location,recovery_region=recovery_region,location
            resetsql=True
            logging.warning("Reset")

        sql_dict={}
        # Iterate over each server
        for server in servers:
            if server.location==location:
                logging.warning(f"Checking server '{server.name}' for read replicas")
                # List the read replicas for the server
                replicas = sql_client.replication_links.list_by_server(resource_group_name, server.name)
                
                # Iterate over each replica
                for replica in replicas:
                    logging.warning(f"Checking replica '{replica.partner_server}' located in '{replica.partner_location}'")
                    # Check if the replica is located in the recovery region
                    if replica.partner_location.replace(' ','').lower() == recovery_region:
                        logging.warning(f"Promoting replica '{replica.partner_server}' to become the primary server")
                        
                        # Promote the replica to become the primary server
                        sql_client.replication_links.begin_failover(
                            resource_group_name,
                            replica.partner_server,
                            replica.partner_database,
                            replica.name
                        )  
                    sql_dict[server.name] = replica.partner_server

                    logging.warning(f"Promoted replica '{replica.partner_server}' of server '{server.name}' to become the primary server")
                else:
                    logging.warning(f"Replica '{replica.partner_server}' of server '{server.name}' is not located in the recovery region")
        else:
            logging.warning(f"Server '{server.name}' is not located in the source region")

        if resetsql:
            return func.HttpResponse(
                    "200",
                    status_code=200)

        logging.warning(f"Promoted Servers With Replica {sql_dict}")

        logging.warning('Changing DB String In App VM')
        # Iterate over each virtual machine and get its public IP address
        pattern = re.compile(r".*App\d+.*")

        for category in json1:
            for resource_type, resources in category.items():
                if resource_type == "PUBLIC_IP_ADDRESS":
                    for resource in resources:
                        name = resource["name"]
                        match = pattern.match(name)
                        if match:
                            public_ip_id = resource['cloudResourceReferenceId']
                            public_ip_name = public_ip_id.split('/')[-1]
                            public_ip_address = network_client.public_ip_addresses.get(recovery_resource_group, public_ip_name)
                            
                            logging.warning(f"Logging in {public_ip_name.split('-')[0]} using {public_ip_address.ip_address}")
                            
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
                                    logging.warning(f"File contents : {file_contents}")

                                    for key,value in sql_dict.items():
                                        file_contents = file_contents.replace(key, value)
                                    logging.warning(f"File contents : {file_contents}")
                                    cmd = f'Set-Content -Path "{file_path}" -Value @"\n{file_contents}\n"@'
                                    session.run_ps(cmd)
                                    cmd = f'Restart-WebAppPool -Name "APPRANIX_myclouditecplatformapi.ciodev.accenture.com"'
                                    session.run_ps(cmd)

                                    logging.warning('File Updated')
                                else:
                                    logging.warning('File does not exist or access denied')
                            except Exception as e:
                                logging.warning(f'An error occurred: {str(e)}')
        
        logging.warning('Changing App Public IP In Web')
        # Initialize an empty dictionary to store the mappings
        ip_mapping = {}

        # Regular expression pattern to match resource names
        ip_pattern = re.compile(r'^(.*?)(Web)(\d+)-ip$')

        # Loop through each item in the JSON data
        for item in json1:
            for resource_type, resources in item.items():
                if resource_type == "PUBLIC_IP_ADDRESS":
                    for resource in resources:
                        ip_id = resource["cloudResourceReferenceId"]
                        match = ip_pattern.match(ip_id)
                        if match:
                            prefix = match.group(1)
                            web_app = match.group(2)
                            number = match.group(3)
                            
                            public_ip_id = resource['cloudResourceReferenceId']
                            public_ip_name = public_ip_id.split('/')[-1]
                            web_ip = network_client.public_ip_addresses.get(recovery_resource_group, public_ip_name)

                            app_id = f"{prefix}App{number}-ip" if web_app == "Web" else f"{prefix}Web{number}-ip"
                            if ip_id != app_id and app_id not in ip_mapping.values():
                                public_ip_name = app_id.split('/')[-1]
                                app_ip = network_client.public_ip_addresses.get(recovery_resource_group, public_ip_name)
                                ip_mapping[str(web_ip.ip_address)] = str(app_ip.ip_address)

        # Print the generated IP mapping dictionary
        logging.warning(f"IP Mapping {ip_mapping}")

        for key,value in ip_mapping.items():
            logging.warning(f"Logging in {key} to update with {value}")
                        
            host = str(key)
            user = os.environ["USER"]
            password = os.environ["PASSWORD"]

            try:
                session = winrm.Session(host, auth=(user, password), transport='ntlm')

                file_path = os.environ["FILE_PATH2"]

                cmd = f'if exist "{file_path}" (echo true) else (echo false)'
                result = session.run_cmd(cmd)

                if result.std_out.strip() == b'true':

                    cmd = f'Get-Content -Path "{file_path}"'
                    result = session.run_ps(cmd)
                    file_contents = result.std_out.decode('utf-8')
                    logging.warning(f"File contents : {file_contents}")

                    # Define the regular expression pattern for an IP address
                    pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

                    # Search for the IP address in the URL
                    match = re.search(pattern, file_contents)
                    if match:
                        # Replace the IP address with the new IP address
                        file_contents = re.sub(pattern, value, file_contents)
                        logging.warning(f"File contents : {file_contents}")
                    else:
                        # If no IP address is found, print the original URL
                        logging.warning(f"No IP Addres Found In The File Path")

                    cmd = f'Set-Content -Path "{file_path}" -Value @"\n{file_contents}\n"@'
                    session.run_ps(cmd)
                    cmd = f'Restart-WebAppPool -Name "APPRANIX_myclouditecplatformapi.ciodev.accenture.com"'
                    session.run_ps(cmd)

                    logging.warning('File Updated')
                else:
                    logging.warning('File does not exist or access denied')
            except Exception as e:
                logging.warning(f'An error occurred: {str(e)}')

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(f"Error occurred: {str(e)}\n. This HTTP triggered function executed successfully.",status_code=400)
    return func.HttpResponse(
                    "200",
                    status_code=200)
