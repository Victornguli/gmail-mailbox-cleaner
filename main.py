from __future__ import print_function
import pickle
import logging
import json
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


logging.basicConfig(
    format = '%(asctime)s  %(levelname)-10s %(processName)s  %(name)s %(message)s', datefmt = "%Y-%m-%d-%H-%M-%S")
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

# If modifying these scopes, delete the file token.pickle.
SCOPES = [
    'https://mail.google.com/'
    ]

# FILTERS = {
#     "from": ["no-reply@financeplan.biz"],
#     "subject": [
#         "Reconciliation Reminder",
#         "Debt Collection Data",
#         "Balance Topup Reminder",
#         "Loan Reminder Results",
#         "Statement Credit Scoring Failure",
#         "Daily Debt Collection Loan Repayments",
#         "Weekly Debt Collection Loan Repayments",
#         "Monthly Debt Collection Loan Repayments",
#         "Service Restoration",
#         "Invoice Payment"
#     ]
# }


# Add custom filters e.g the sender email and subject(s) to be applied to the G-mail filter
FILTERS = {
    "from": [
      "noreply@youtube.com", "digest-noreply@quora.com",
      "no-reply@mail.instagram.com", "info@updates.intherooms.com"
      "trending-stories-noreply@quora.com", "noreply@medium.com",
      "noreply-utos@google.com", "hello@stackshare.io"
    ]
}


def getCredentials():
    """Retrieves user credentials for auth"""
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return creds


def buildService(creds):
    """Builds the GMAIL API service given the supplied credentials"""
    service = None
    if creds is not None:
        service = build('gmail', 'v1', credentials=creds)
    return service


def getMessageList(service, user_id, page_token = None, max_results = None, q=None, **kwargs):
    """
    Retrieves user messages
    @param service: The api client connection
    @type service: build
    @param page_token: Next page token if supplied
    @type page_token: str | None
    @param: max_results: Maximum number of results per request 
    @type max_results: int | None
    @param user_id: User id to be supplied in the service execution
    @type user_id: str
    @param q: Optional search query to be applied
    @type q: str | None
    """
    try:
        if page_token is not None:
            kwargs.update(pageToken = page_token)
        if max_results is not None and isinstance(max_results, int):
            kwargs.update(maxResults = max_results)
        if q is not None:
            kwargs.update(q=q)
        messages = service.users().messages().list(userId=user_id, **kwargs).execute()
        return messages
    except Exception as ex:
        logging.exception('GetMessageList Exception: %s'%ex)
    return None


def getMessage(service, message_id, user_id, format=None, **kwargs):
    """Retrieves a single message"""
    try:
        if format is not None:
            kwargs.update(format=format)
        message = service.users().messages().get(userId=user_id, id=message_id, **kwargs).execute()
        return message
    except Exception as ex:
        logging.exception('GetMessage Exception: %s'%ex)
    return None


def formatQuery(filters = None):
    filter_query = ''
    try:
        if filters is not None:
            subject = filters.get('subject', None)
            sender = filters.get('from', None)
            if subject is not None:
                subject_text = 'subject:\"%s\"' % subject[0]
                if len(subject) > 1:
                    for i in subject[1:]:
                        subject_text += ' OR \"%s\"' % i
                filter_query += subject_text
            if sender is not None:
                sender_text = ' from:\"%s\"' % sender.pop(0)
                for i in sender:
                    sender_text += ' OR \"%s\"' % i
                filter_query += sender_text
            print(filter_query)
            return filter_query
    except Exception as ex:
        logging.exception('ConstructFilter Exception: %s' % ex)
    return filter_query


def batchDelete(service, message_ids, user_id, **kwargs):
    """Deletes multiple messages given the message_ids"""
    try:
        service.users().messages().batchDelete(userId = user_id, body = message_ids).execute()
        return True
    except Exception as ex:
        logging.exception('BatchFilter Exception: %s' % ex)
    return False


def get_message_ids(message_list):
    """Retrieves message ids from a messages list response to be used for batch actions"""
    message_ids = []
    try:
        message_ids = [message.get('id', None) for message in message_list]
    except Exception as ex:
        logging.exception('Get Message Ids Exception: %s' % ex)
    return message_ids


def execute_batch_delete(filters, service, max_results = 500):
    """Executes the batch delete method"""
    try:
        query = formatQuery(filters)
        # Retrieves messages
        messages_response = getMessageList(service = service, user_id = 'me', max_results = max_results, q = query)
        messages_len = 0
        if messages_response is not None:
            messages = messages_response.get('messages', '')
            messages_len += len(messages)
            if messages:
                message_ids = get_message_ids(messages)
                batch_action = batchDelete(service = service, user_id = 'me', message_ids = {"ids": message_ids})
                if batch_action:
                    print('Batch deleted %s messages' % len(messages))
                else:
                    print('Batch delete failed')

            # If Message list has a nextPage token call getMessageList to fetch the nextPage list of messageIds
            while messages_response.get('nextPageToken', None):
                # print(messages_response.get('nextPageToken', None))
                messages_response = getMessageList(
                    service = service, user_id = 'me', page_token = messages_response.get('nextPageToken'),
                    max_results = 500, q = query)
                if messages_response is not None:
                    messages = messages_response.get('messages', '')
                    messages_len += len(messages)
                    if messages:
                        message_ids = get_message_ids(messages)
                        batch_action = batchDelete(
                            service = service, user_id = 'me', message_ids = {"ids": message_ids})
                        if batch_action:
                            print('Batch deleted %s messages' % len(messages))
                        else:
                            print('Batch delete failed')
                        # print('Fetched %s messages' % len(messages))
            print('Batch delete is complete. %s messages deleted' % messages_len)
            # print('Message fetch complete. %s messages found' %messages_len)
    except Exception as ex:
        logging.exception('Execute Batch Delete Exception: %s' % ex)
    # return False


def main():
    """Main execution flow"""
    print('########################################### \n')
    credentials = getCredentials()
    service = buildService(credentials)
    execute_batch_delete(FILTERS, service, 500)


if __name__ == '__main__':
    main()
