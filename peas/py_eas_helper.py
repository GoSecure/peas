__author__ = 'Adam Rutherford'

from twisted.internet import reactor

from peas.eas_client import activesync

def body_result(result, emails, num_emails):
    emails.append(result['Properties']['Body'])

    # Stop after receiving final email.
    if len(emails) == num_emails:
        reactor.stop()

def sync_result(result, fid, activesync_client, emails):
    assert hasattr(result, 'keys')

    num_emails = len(result.keys())

    for fetch_id in result.keys():
        activesync_client.add_operation(activesync_client.fetch, collectionId=fid, serverId=fetch_id,
            fetchType=4, mimeSupport=2).addBoth(body_result, emails, num_emails)

def fsync_result(result, activesync_client, emails):
    for (fid, finfo) in result.items():
        if finfo['DisplayName'] == 'Inbox':
            activesync_client.add_operation(activesync_client.sync, fid).addBoth(sync_result, fid, activesync_client, emails)
            break

def prov_result(success, activesync_client, emails):
    if success:
        activesync_client.add_operation(activesync_client.folder_sync).addBoth(fsync_result, activesync_client, emails)
    else:
        reactor.stop()


def extract_emails(creds):
    emails = []

    activesync_client = eas_client.activesync.ActiveSync(creds['domain'], creds['user'], creds['password'],
            creds['server'], True, device_id=creds['device_id'], verbose=False)

    activesync_client.add_operation(activesync_client.provision).addBoth(prov_result, activesync_client, emails)

    reactor.run()

    return emails
