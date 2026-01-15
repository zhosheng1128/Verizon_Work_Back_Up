import tableauserverclient as TSC
import requests
import xml.etree.ElementTree as ET
from pathlib import Path

# Username and Password Variables
tab_user_name = 'SVC-NATCOMP'
tab_password = 'NCRMServiceAccount01012018'
site = 'ComplianceBi'
server_url = 'https://mtr.vzwcorp.com/'
api = '3.17'


### TSC Sign-In (Python API Wrapper)
def get_tab_auth_server():
    tab_auth = TSC.TableauAuth(tab_user_name, tab_password, site_id = site)
    server = TSC.Server(server_url, use_server_version = True)

    return server, tab_auth


### API Sign-Ins
def get_sign_in_xml():
    '''
    Return the XML body of the Tableau Server sign-in request
    '''

    return f'''
        <tsRequest>
	        <credentials name="{tab_user_name}" password="{tab_password}" >
  		        <site contentUrl="{site}" />
	        </credentials>
        </tsRequest>
    '''

def sign_in():
    '''
    Send POST request to Tableau Server to sign in
    '''
    resp = requests.post(
        f"{server_url}/api/{api}/auth/signin", data=get_sign_in_xml())

    return resp.content

def get_token_from_xml(resp_content):
    resp_xml = ET.fromstring(resp_content)

    return resp_xml.find('.//{*}credentials').attrib['token']


def get_site_luid_from_xml(resp_content):
    resp_xml = ET.fromstring(resp_content)

    return resp_xml.find('.//{*}site').attrib['id']


## Get Job Info
def get_job(job_id):
    '''
    Simple GET request to get job info

    Has no parameters, uses X-Tableau-Auth header
    '''

    auth = sign_in()
    token = get_token_from_xml(auth)
    site_luid = get_site_luid_from_xml(auth)


    headers = {
        'X-Tableau-Auth': token
    }

    resp = requests.get(
        f"{server_url}/api/{api}/sites/{site_luid}/jobs/{job_id}", headers=headers)

    return resp.content

def get_data_source_id(extract_name):
    server, tab_auth = get_tab_auth_server()

    with server.auth.sign_in(tab_auth):
    # all_datasources = list(TSC.Pager(server.datasources))
    # print(all_datasources)
        req_options = TSC.RequestOptions()
        req_options.filter.add(TSC.Filter(
            TSC.RequestOptions.Field.Name, TSC.RequestOptions.Operator.Equals, extract_name))
        ds, paginator = server.datasources.get(req_options=req_options)
        print(ds)

def refresh_tableau_extract(id):
    server, tab_auth = get_tab_auth_server()

    with server.auth.sign_in(tab_auth):
        resource = server.datasources.get_by_id(id)
        job = server.datasources.refresh(resource)
        print(f"Update job posted (ID: {job.id})")
        print("Waiting for job...")
        # `wait_for_job` will throw if the job isn't executed successfully
        job = server.jobs.wait_for_job(job)
        print("Job finished succesfully")
        print(vars(job))

def get_etl_password():
    with open(Path('//tdcwpnc4vd003/d$/ssis_packages/TERADATA/TDLOGON/TD_Load_ETL.LOGON'),"r") as f:
        for line in f:
            user, pwd = line.strip().split(',')
    user = user.split('/')[1]
    pwd = pwd[1:-1]
    return user, pwd