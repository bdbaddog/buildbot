# This file is part of Buildbot.  Buildbot is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Buildbot Team Members
# Copyright 2013 (c) Mamba Team

from __future__ import absolute_import
from __future__ import print_function

import json
import logging


from dateutil.parser import parse as dateparse

from twisted.python import log

from buildbot.util import bytes2NativeString
# from buildbot.changes.github import PullRequestMixin

_HEADER_EVENT = b'X-Event-Key'
_HEADER_CT = b'Content-Type'

_VERBOSE_LOGGING = True

class BitbucketEventHandler(object):

    def __init__(self, secret, strict, codebase=None, bitbucket_property_whitelist=None):
        if _VERBOSE_LOGGING:
            log.msg("IN __init__")
        self._secret = secret
        self._strict = strict
        self._codebase = codebase
        self.bitbucket_property_whitelist = bitbucket_property_whitelist
        if bitbucket_property_whitelist is None:
            self.bitbucket_property_whitelist = []

        if self._strict and not self._secret:
            raise ValueError('Strict mode is requested '
                             'while no secret is provided')

    def process(self, request):
        if _VERBOSE_LOGGING:
            log.msg("IN process")

        payload = self._get_payload(request)

        event_type = request.getHeader(_HEADER_EVENT)
        event_type = bytes2NativeString(event_type)
        if _VERBOSE_LOGGING:
            log.msg("X-Bitbucket-Event: {}".format(event_type), logLevel=logging.DEBUG)

        event_type = event_type.replace(':','_')
        handler = getattr(self, 'handle_{}'.format(event_type), None)

        if handler is None:
            raise ValueError('Unknown event: {}'.format(event_type))

        return handler(payload, event_type)

    def _get_payload(self, request):
        content = request.content.read()
        content = bytes2NativeString(content)

        content_type = request.getHeader(_HEADER_CT)
        content_type = bytes2NativeString(content_type)

        if content_type == 'application/json':
            payload = json.loads(content)
        elif content_type == 'application/x-www-form-urlencoded':
            # pretty sure this is not longer applicable
            payload = json.loads(request.args['payload'][0])
        else:
            raise ValueError('Unknown content type: {}'.format(content_type))

        if _VERBOSE_LOGGING:
                log.msg("Payload: {}".format(payload), logLevel=logging.DEBUG)

        return payload

    def handle_ping(self, _, __):
        return [], 'git'

    def handle_repo_push(self, payload, event):
        """
        Handle bitbucket repo:push payload

        :param payload: parsed JSON payload
        :param event: Always None
        :return: tuple (changes, scm) changes is list of dicts, scm is scm type (git,hg)
        """
        # This field is unused:
        user = payload['actor']['username']
        repo = payload['repository']['name']
        repo_url = payload['repository']['links']['html']['href']
        # NOTE: what would be a reasonable value for project?
        # project = request.args.get('project', [''])[0]
        project = payload['repository']['name']

        (changes, scm) = self._process_push_change(payload, user, repo, repo_url, project,
                                       event)

        if _VERBOSE_LOGGING:
            log.msg("Received {} changes from Bitbucket".format(len(changes)))

        return changes, scm

    def handle_pullrequest_fulfilled(self, payload, event):
        """
        Handle bitbucket pullrequest:fullfilled payload
        :param payload: parsed JSON payload
        :param event: Always None
        :return: tuple (changes, scm) changes is list of dicts, scm is scm type (git,hg)
        """
        changes = []
        scm = payload['repository']['scm']

        pullrequest = payload['pullrequest']

        number = pullrequest['id']

        branch = pullrequest['destination']['branch']['name']
        commit = pullrequest['merge_commit']
        title = pullrequest['title']
        comments = pullrequest['description']
        destination = pullrequest['destination']

        log.msg('Processing Bitbucket PR #{}'.format(number),
                logLevel=logging.DEBUG)

        action = pullrequest.get('state')
        if action not in ('MERGED', 'reopened', 'synchronize'):
            log.msg("Bitbucket PR #{} {}, ignoring".format(number, action))
            return changes, scm

        # properties = self.extractProperties(pullrequest, domain='bitbucket')
        properties = {'event': event}

        change = {
            'revision': commit['hash'],
            'when_timestamp': dateparse(pullrequest['updated_on']),
            'branch': branch,
            'revlink': pullrequest['links']['html']['href'],
            'repository': payload['repository']['links']['html']['href'],
            'project': payload['repository']['name'],
            'category': 'pull',
            # TODO: Get author name based on login id using txbitbucket module
            'author': payload['actor']['display_name'],
            'comments': 'bitbucket Pull Request #{0} ({1}) {2}\n{3}'.format(
                number, commit['hash'], title, comments),
            'properties': properties,
        }

        if callable(self._codebase):
            change['codebase'] = self._codebase(payload)
        elif self._codebase is not None:
            change['codebase'] = self._codebase

        changes.append(change)

        log.msg("Received {} changes from Bitbucket PR #{}".format(
            len(changes), number))
        return changes, scm

    def _process_push_change(self, payload, user, repo, repo_url, project, event):
        """
        Consumes the JSON as a python object and actually starts the build.

        :arguments:
            payload
                Python Object that represents the JSON sent by Bitbucket Service
                Hook.
        """
        change_list = []

        changes = payload['push']['changes']
        for change in changes:

            # TODO: Handle difference with hg and mercurial and other cases in :
            # https://confluence.atlassian.com/bitbucket/event-payloads-740262817.html#EventPayloads-Push
            branch = change['new']['name']
            commits = change['commits']
            for commit in commits:
                if _VERBOSE_LOGGING: log.msg("Processing %s"%commit)
                # files = []

                when_timestamp = dateparse(commit['date'])

                if _VERBOSE_LOGGING: log.msg("TIME: {}  -> {}".format(commit['date'], when_timestamp))

                if _VERBOSE_LOGGING: log.msg("New revision: {}".format(commit['hash'][:8]))

                if commit['author'].get('user',False):
                    author = commit['author']['user'].get('display_name','Unknown')
                else:
                    author = u'Unknown'

                change = {
                    'author': u'{} <{}>'.format(author,
                                               commit['author']['raw']),
                    # 'files': 'Not in post',
                    'comments': commit['message'],
                    'revision': commit['hash'],
                    'when_timestamp': when_timestamp,
                    'branch': branch,
                    'revlink': commit['links']['html']['href'],
                    'repository': repo_url,
                    'project': project,
                    'properties': {
                        # 'Bitbucket_distinct': commit.get('distinct', True),
                        'event': event,
                    },
                }
                if _VERBOSE_LOGGING: log.msg("Processed:%s"%change)

                if callable(self._codebase):
                    change['codebase'] = self._codebase(payload['push'])
                elif self._codebase is not None:
                    change['codebase'] = self._codebase

                if _VERBOSE_LOGGING: log.msg("CHANGE:%s"%change)
                change_list.append(change)

        return (change_list, payload['repository']['scm'])

def getChanges(request, options=None):
    """
    Responds only to POST events and starts the build process

    :arguments:
        request
            the http request object
    """
    if options is None:
        options = {}

    log.msg("Processing BitbucketEventHandler")

    klass = options.get('class', BitbucketEventHandler)

    handler = klass(options.get('secret', None),
                    options.get('strict', False),
                    options.get('codebase', None),
                    options.get('bitbucket_property_whitelist', None))
    return handler.process(request)

