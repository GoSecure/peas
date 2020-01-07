########################################################################
# Modified 2016 from code Copyright (C) 2013 Sol Birnbaum
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA  02110-1301, USA.
########################################################################\

import ssl
import base64

# https://docs.python.org/2/library/xml.html#xml-vulnerabilities
from lxml import etree as ElementTree

from peas.pyActiveSync.utils.as_code_pages import as_code_pages
from peas.pyActiveSync.utils.wbxml import wbxml_parser
from peas.pyActiveSync.client.storage import storage

from peas.pyActiveSync.client.FolderSync import FolderSync
from peas.pyActiveSync.client.Sync import Sync
from peas.pyActiveSync.client.GetItemEstimate import GetItemEstimate
from peas.pyActiveSync.client.Provision import Provision
from peas.pyActiveSync.client.Search import Search
from peas.pyActiveSync.client.ItemOperations import ItemOperations

from peas.pyActiveSync.objects.MSASHTTP import ASHTTPConnector
from peas.pyActiveSync.objects.MSASCMD import as_status
from peas.pyActiveSync.objects.MSASAIRS import airsync_FilterType, airsync_Conflict, airsync_MIMETruncation, \
    airsync_MIMESupport, \
    airsync_Class, airsyncbase_Type


# Create WBXML parser instance.
parser = wbxml_parser(*as_code_pages.build_as_code_pages())


def _parse_for_emails(res, emails):

    data = str(res)

    etparser = ElementTree.XMLParser(recover=True)
    tree = ElementTree.fromstring(data, etparser)

    for item in tree.iter('{airsync:}ApplicationData'):
        s = ElementTree.tostring(item)
        emails.append(s)


def as_request(as_conn, cmd, wapxml_req):
    res = as_conn.post(cmd, parser.encode(wapxml_req))
    wapxml_res = parser.decode(res)
    return wapxml_res


#Provision functions
def do_apply_eas_policies(policies):
    for policy in policies.keys():
        pass
    return True


def do_provision(as_conn, device_info):
    provision_xmldoc_req = Provision.build("0", device_info)
    as_conn.set_policykey("0")
    provision_xmldoc_res = as_request(as_conn, "Provision", provision_xmldoc_req)
    status, policystatus, policykey, policytype, policydict, settings_status = Provision.parse(provision_xmldoc_res)
    as_conn.set_policykey(policykey)
    storage.update_keyvalue("X-MS-PolicyKey", policykey)
    storage.update_keyvalue("EASPolicies", repr(policydict))
    if do_apply_eas_policies(policydict):
        provision_xmldoc_req = Provision.build(policykey)
        provision_xmldoc_res = as_request(as_conn, "Provision", provision_xmldoc_req)
        status, policystatus, policykey, policytype, policydict, settings_status = Provision.parse(provision_xmldoc_res)
        if status == "1":
            as_conn.set_policykey(policykey)
            storage.update_keyvalue("X-MS-PolicyKey", policykey)


#Sync function
def do_sync(as_conn, curs, collections, emails_out):

    as_sync_xmldoc_req = Sync.build(storage.get_synckeys_dict(curs), collections)
    res = as_conn.post("Sync", parser.encode(as_sync_xmldoc_req))
    if res == '':
        pass
    else:
        collectionid_to_type_dict = storage.get_serverid_to_type_dict()
        as_sync_xmldoc_res = parser.decode(res)

        _parse_for_emails(as_sync_xmldoc_res, emails_out)

        sync_res = Sync.parse(as_sync_xmldoc_res, collectionid_to_type_dict)
        storage.update_items(sync_res)
        return sync_res


#GetItemsEstimate
def do_getitemestimates(as_conn, curs, collection_ids, gie_options):
    getitemestimate_xmldoc_req = GetItemEstimate.build(storage.get_synckeys_dict(curs), collection_ids, gie_options)
    getitemestimate_xmldoc_res = as_request(as_conn, "GetItemEstimate", getitemestimate_xmldoc_req)

    getitemestimate_res = GetItemEstimate.parse(getitemestimate_xmldoc_res)
    return getitemestimate_res


def getitemestimate_check_prime_collections(as_conn, curs, getitemestimate_responses, emails_out):
    has_synckey = []
    needs_synckey = {}
    for response in getitemestimate_responses:
        if response.Status == "1":
            has_synckey.append(response.CollectionId)
        elif response.Status == "2":
            pass
        elif response.Status == "3":
            pass
            needs_synckey.update({response.CollectionId: {}})
            has_synckey.append(
                response.CollectionId)  #technically *will* have synckey after do_sync() need end of function
        else:
            pass
    if len(needs_synckey) > 0:
        do_sync(as_conn, curs, needs_synckey, emails_out)
    return has_synckey, needs_synckey


def sync(as_conn, curs, collections, collection_sync_params, gie_options, emails_out):
    getitemestimate_responses = do_getitemestimates(as_conn, curs, collections, gie_options)

    has_synckey, just_got_synckey = getitemestimate_check_prime_collections(as_conn, curs, getitemestimate_responses,
                                                                            emails_out)

    if (len(has_synckey) < collections) or (len(just_got_synckey) > 0):  #grab new estimates, since they changed
        getitemestimate_responses = do_getitemestimates(as_conn, curs, has_synckey, gie_options)

    collections_to_sync = {}

    for response in getitemestimate_responses:
        if response.Status == "1":
            if int(response.Estimate) > 0:
                collections_to_sync.update({response.CollectionId: collection_sync_params[response.CollectionId]})
        else:
            pass

    if len(collections_to_sync) > 0:
        sync_res = do_sync(as_conn, curs, collections_to_sync, emails_out)

        if sync_res:
            while True:
                for coll_res in sync_res:
                    if coll_res.MoreAvailable == None:
                        del collections_to_sync[coll_res.CollectionId]
                if len(collections_to_sync.keys()) > 0:
                    sync_res = do_sync(as_conn, curs, collections_to_sync, emails_out)
                else:
                    break


def disable_certificate_verification():

    ssl._create_default_https_context = ssl._create_unverified_context


def extract_emails(creds):

    storage.erase_db()
    storage.create_db_if_none()

    conn, curs = storage.get_conn_curs()
    device_info = {"Model": "1234", "IMEI": "123457",
                   "FriendlyName": "My pyAS Client 2", "OS": "Python", "OSLanguage": "en-us", "PhoneNumber": "NA",
                   "MobileOperator": "NA", "UserAgent": "pyAS"}

    #create ActiveSync connector
    as_conn = ASHTTPConnector(creds['server'])  #e.g. "as.myserver.com"
    as_conn.set_credential(creds['user'], creds['password'])

    #FolderSync + Provision
    foldersync_xmldoc_req = FolderSync.build(storage.get_synckey("0"))
    foldersync_xmldoc_res = as_request(as_conn, "FolderSync", foldersync_xmldoc_req)
    changes, synckey, status = FolderSync.parse(foldersync_xmldoc_res)
    if 138 < int(status) < 145:
        ret = as_status("FolderSync", status)
        do_provision(as_conn, device_info)
        foldersync_xmldoc_res = as_request(as_conn, "FolderSync", foldersync_xmldoc_req)
        changes, synckey, status = FolderSync.parse(foldersync_xmldoc_res)
        if 138 < int(status) < 145:
            ret = as_status("FolderSync", status)
            raise Exception("Unresolvable provisioning error: %s. Cannot continue..." % status)
    if len(changes) > 0:
        storage.update_folderhierarchy(changes)
        storage.update_synckey(synckey, "0", curs)
        conn.commit()

    collection_id_of = storage.get_folder_name_to_id_dict()

    inbox = collection_id_of["Inbox"]

    collection_sync_params = {
        inbox:
            {  #"Supported":"",
               #"DeletesAsMoves":"1",
               #"GetChanges":"1",
               "WindowSize": "512",
               "Options": {
                   "FilterType": airsync_FilterType.OneMonth,
                   "Conflict": airsync_Conflict.ServerReplacesClient,
                   "MIMETruncation": airsync_MIMETruncation.TruncateNone,
                   "MIMESupport": airsync_MIMESupport.SMIMEOnly,
                   "Class": airsync_Class.Email,
                   #"MaxItems":"300", #Recipient information cache sync requests only. Max number of frequently used contacts.
                   "airsyncbase_BodyPreference": [{
                                                      "Type": airsyncbase_Type.HTML,
                                                      "TruncationSize": "1000000000",  # Max 4,294,967,295
                                                      "AllOrNone": "1",
                                                      # I.e. Do not return any body, if body size > tuncation size
                                                      #"Preview": "255", # Size of message preview to return 0-255
                                                  },
                                                  {
                                                      "Type": airsyncbase_Type.MIME,
                                                      "TruncationSize": "3000000000",  # Max 4,294,967,295
                                                      "AllOrNone": "1",
                                                      # I.e. Do not return any body, if body size > tuncation size
                                                      #"Preview": "255", # Size of message preview to return 0-255
                                                  }
                   ],
                   #"airsyncbase_BodyPartPreference":"",
                   #"rm_RightsManagementSupport":"1"
               },
               #"ConversationMode":"1",
               #"Commands": {"Add":None, "Delete":None, "Change":None, "Fetch":None}
               },
    }

    gie_options = {
        inbox:
            {  #"ConversationMode": "0",
               "Class": airsync_Class.Email,
               "FilterType": airsync_FilterType.OneMonth
               #"MaxItems": "" #Recipient information cache sync requests only. Max number of frequently used contacts.
               },
    }

    collections = [inbox]
    emails = []

    sync(as_conn, curs, collections, collection_sync_params, gie_options, emails)

    if storage.close_conn_curs(conn):
        del conn, curs

    return emails


def get_unc_listing(creds, unc_path, username=None, password=None):

    # Create ActiveSync connector.
    as_conn = ASHTTPConnector(creds['server'])
    as_conn.set_credential(creds['user'], creds['password'])

    # Perform request.
    search_xmldoc_req = Search.build(unc_path, username=username, password=password)
    search_xmldoc_res = as_request(as_conn, "Search", search_xmldoc_req)

    # Parse response.
    status, records = Search.parse(search_xmldoc_res)
    return records


def get_unc_file(creds, unc_path, username=None, password=None):

    # Create ActiveSync connector.
    as_conn = ASHTTPConnector(creds['server'])
    as_conn.set_credential(creds['user'], creds['password'])

    # Perform request.
    operation = {'Name': 'Fetch', 'Store': 'DocumentLibrary', 'LinkId': unc_path}
    if username != None:
        operation['UserName'] = username
    if password != None:
        operation['Password'] = password
    operations = [operation]

    xmldoc_req = ItemOperations.build(operations)
    xmldoc_res = as_request(as_conn, "ItemOperations", xmldoc_req)
    responses = ItemOperations.parse(xmldoc_res)

    # Parse response.
    op, _, path, info, _ = responses[0]

    if info and info['Data']:
        return base64.b64decode(info['Data'])
    else:
        return '[*] Unable to fetch file.'
