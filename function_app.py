import azure.functions as func
from azure.mgmt.sql import SqlManagementClient
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.mgmt.web import WebSiteManagementClient
import json
import os

import requests
import logging
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


def failover(rec_res_group_name,app_service_name,web_client,resource_client,client, resource_group_name,locations,recovery_region,rec_id):
    server=client.servers.list_by_resource_group(resource_group_name)
    # logging.info(server)
    server_list=[]
    for i in server:
        server_list.append(i.name)
    logging.info(server_list)
    if len(server_list) == 0:
        logging.info("404 : No Server found")
        exit()
    def update_conn_string(setting_name, new_setting_value):
        app_settings = web_client.web_apps.list_application_settings(rec_res_group_name, app_service_name)

        app_settings.properties[setting_name] = new_setting_value

        web_client.web_apps.update_application_settings(rec_res_group_name, app_service_name,app_settings)

        logging.info(f"Updated the application setting '{setting_name}' with the value '{new_setting_value}'.")
    def store_json_in_existing_container(json_data, container_name, file_name, connection_string):
        try:
            # Create a BlobServiceClient using the connection string
            blob_service_client = BlobServiceClient.from_connection_string(connection_string)

            # Get the container client
            container_client = blob_service_client.get_container_client(container_name)

            # Convert JSON data to bytes
            json_bytes = json.dumps(json_data).encode('utf-8')

            # Create a blob client
            blob_client = container_client.get_blob_client(file_name)

            # Upload the JSON data to the blob
            blob_client.upload_blob(json_bytes, overwrite=True)

            logging.info(f"JSON file '{file_name}' uploaded successfully to container '{container_name}'.")
        except Exception as e:
            logging.info(f"Error uploading JSON file: {str(e)}")
    def partner_server_rg(sql_server_name):
        for resource in resource_client.resources.list(filter=f"resourceType eq 'Microsoft.Sql/servers' and name eq '{sql_server_name}'"):
            server_resource_group = resource.id.split('/')[4]  # Extract resource group name from resource ID
            break
        return server_resource_group
    def make_fail_over(resource_group_name,server_name, database_name, recovery_region):
        primary=client.replication_links.list_by_database(resource_group_name, server_name, database_name)
        database_link_id = None
        replica_server = None
        for l in primary:
            # logging.info(l)
            database_link_id = l.name
            replica_server = l.partner_server
            
            # logging.info(l.partner_location.replace(" ", "").lower(), recovery_region)
            if l.partner_location.replace(" ", "").lower() == recovery_region.replace(" ", "").lower() and l.partner_role == "Secondary":
                replica_server_rg = partner_server_rg(replica_server)
                operation = client.replication_links.begin_failover(replica_server_rg, replica_server, database_name,database_link_id)
                source = {
                "resource_grp_name" : resource_group_name,
                "server_name_pri" : server_name,
                "database_name_pri" : database_name,
                "link_id"  : database_link_id
            }
    for i in server_list:
        database_a=client.databases.list_by_server(resource_group_name,i)
        for j in database_a:
            if j.location==locations:
                if j.name != "master" and j.secondary_type == None:
                    # logging.info(i,j.name, recovery_region)
                    make_fail_over(resource_group_name,i,j.name, recovery_region)
    logging.info("End Of Function")


@app.function_name(name="HttpTrigger")
@app.route(route="", auth_level=func.AuthLevel.ANONYMOUS)
def HttpTrigger(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Python HTTP trigger function processed a request.')
        request_json = req.get_json()
        logging.info(request_json)
        deployment_name = request_json['recoveryName']
        primary_resource_metadata_url = request_json['resourceMapping']['primaryResourceMetadataPath']
        recovered_metadata_url = request_json['resourceMapping']['recoveredMetadataPath']
        rec_id = request_json['recoveryId']
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
        app_service_name = None
        for item in json2:
            if 'APP_SERVICE' in item:
                app_service_name = deployment_name+"-"+item['APP_SERVICE'][0]['name']
                break
        rec_res_group_name = None
        for item in json2:
            if 'RESOURCE_GROUP' in item:
                rec_res_group_name = deployment_name+"-"+item['RESOURCE_GROUP'][0]['name']
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

        client = SqlManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        web_client = WebSiteManagementClient(credential, subscription_id)
        failover(rec_res_group_name,app_service_name,web_client,resource_client ,client, resource_group_name, location, recovery_region,rec_id)

        return func.HttpResponse(
            "200",
            status_code=200)

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(f"Hello, {str(e)}. This HTTP triggered function executed successfully.", status_code=400)
