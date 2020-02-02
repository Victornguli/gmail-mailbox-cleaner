from __future__ import print_function
import pickle
import logging
import json
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


logging.basicConfig( format = '%(asctime)s  %(levelname)-10s %(processName)s  %(name)s %(message)s', datefmt =  "%Y-%m-%d-%H-%M-%S")


# If modifying these scopes, delete the file token.pickle.
SCOPES = [
    'https://mail.google.com/'
    ]


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


def constructFilter(subject=None):
    """Constructs a filter to be passed to the getMessagesList function. Currently only applies subject filter."""
    try:
        if subject is not None:
            subject_text = 'subject:\"%s\"'%subject[0]
            if len(subject) > 1:
                for i in subject[1:]:
                    subject_text += ' OR \"%s\"'%i
            return subject_text
    except Exception as ex:
        logging.exception('ConstructFilter Exception: %s'%ex)
    return ''


def batchDelete(service, message_ids, user_id, **kwargs):
    """Deletes multiple messages given the message_ids"""
    try:
        deleted_messages = service.users().messages().batchDelete(userId=user_id, body=message_ids).execute()
    except Exception as ex:
        logging.exception('BatchFilter Exception: %s'%ex)
    return 'Failed'


def main():
    """Main execution flow"""
    credentials = getCredentials()
    service = buildService(credentials)

    # Add custom filters e.g the sender email, email subject to be applied in the gmail filter, etc
    filters = {
        "from": "target@email.test",
        "subject": [
            "Daily Newsletter Mail"
            ]
    }
    query = constructFilter(filters.get('subject'))
    # Retrives messages
    messages_response = getMessageList(service=service, user_id='me', max_results=500, q=query)
    message_ids = []
    if messages_response is not None:
         # If Message list has a nextPage token call getMessageList
        while (messages_response.get('nextPageToken', None)):
            messages_response = getMessageList(
                service=service, user_id='me', page_token = messages_response.get('nextPageToken'), max_results=5, q=query)
            if messages_response is not None:
                messages = messages_response.get('messages', None)
                if messages is not None:
                    message_ids += [message.get('id', None) for message in messages]
                    batchDelete(service=service, user_id='me', message_ids={"ids": message_ids})
        if messages_response is not None:
            messages = messages_response.get('messages', None)
            if messages is not None:
                message_ids += [message.get('id', None) for message in messages]
                batchDelete(service=service, user_id='me', message_ids={"ids": message_ids})
        print('Deleted %s messages successfully'%len(message_ids))


if __name__ == '__main__':
    main()