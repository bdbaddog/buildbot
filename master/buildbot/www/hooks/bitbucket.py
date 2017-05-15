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
from buildbot.changes.github import PullRequestMixin

_HEADER_EVENT = b'X-Event-Key'
_HEADER_CT = b'Content-Type'



class BitbucketEventHandler(PullRequestMixin):

    def __init__(self, secret, strict, codebase=None, bitbucket_property_whitelist=None):
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
        log.msg("IN process")

        payload = self._get_payload(request)

        event_type = request.getHeader(_HEADER_EVENT)
        event_type = bytes2NativeString(event_type)
        log.msg("X-Bitbucket-Event: {}".format(
            event_type), logLevel=logging.DEBUG)

        event_type = event_type.split(':')[1]
        handler = getattr(self, 'handle_{}'.format(event_type), None)

        if handler is None:
            raise ValueError('Unknown event: {}'.format(event_type))

        return handler(payload, event_type)

    def _get_payload(self, request):
        content = request.content.read()
        content = bytes2NativeString(content)

        # signature = request.getHeader(_HEADER_SIGNATURE)
        # signature = bytes2NativeString(signature)
        #
        # if not signature and self._strict:
        #     raise ValueError('Request has no required signature')
        #
        # if self._secret and signature:
        #     try:
        #         hash_type, hexdigest = signature.split('=')
        #     except ValueError:
        #         raise ValueError(
        #             'Wrong signature format: {}'.format(signature))
        #
        #     if hash_type != 'sha1':
        #         raise ValueError('Unknown hash type: {}'.format(hash_type))
        #
        #     mac = hmac.new(unicode2bytes(self._secret),
        #                    msg=unicode2bytes(content),
        #                    digestmod=sha1)
        #     # NOTE: hmac.compare_digest should be used, but it's only available
        #     # starting Python 2.7.7
        #     if mac.hexdigest() != hexdigest:
        #         raise ValueError('Hash mismatch')

        content_type = request.getHeader(_HEADER_CT)
        content_type = bytes2NativeString(content_type)

        if content_type == 'application/json':
            payload = json.loads(content)
        elif content_type == 'application/x-www-form-urlencoded':
            # pretty sure this is not longer applicable
            payload = json.loads(request.args['payload'][0])
        else:
            raise ValueError('Unknown content type: {}'.format(content_type))

        log.msg("Payload: {}".format(payload), logLevel=logging.DEBUG)

        return payload

    def handle_ping(self, _, __):
        return [], 'git'

    def handle_push(self, payload, event):
        # This field is unused:
        user = payload['actor']['username']
        repo = payload['repository']['name']
        repo_url = payload['repository']['links']['html']['href']
        # NOTE: what would be a reasonable value for project?
        # project = request.args.get('project', [''])[0]
        project = payload['repository']['name']

        changes = self._process_push_change(payload['push'], user, repo, repo_url, project,
                                       event)

        log.msg("Received {} changes from Bitbucket".format(len(changes)))

        return changes, 'git'

    def handle_pull_request(self, payload, event):
        changes = []
        number = payload['number']
        refname = 'refs/pull/{}/merge'.format(number)
        commits = payload['pull_request']['commits']
        title = payload['pull_request']['title']
        comments = payload['pull_request']['body']

        log.msg('Processing Bitbucket PR #{}'.format(number),
                logLevel=logging.DEBUG)

        action = payload.get('action')
        if action not in ('opened', 'reopened', 'synchronize'):
            log.msg("Bitbucket PR #{} {}, ignoring".format(number, action))
            return changes, 'git'

        properties = self.extractProperties(payload['pull_request'])
        properties.update({'event': event})

        change = {
            'revision': payload['pull_request']['head']['sha'],
            'when_timestamp': dateparse(payload['pull_request']['created_at']),
            'branch': refname,
            'revlink': payload['pull_request']['_links']['html']['href'],
            'repository': payload['repository']['html_url'],
            'project': payload['pull_request']['base']['repo']['full_name'],
            'category': 'pull',
            # TODO: Get author name based on login id using txbitbucket module
            'author': payload['sender']['login'],
            'comments': 'bitbucket Pull Request #{0} ({1} commit{2})\n{3}\n{4}'.format(
                number, commits, 's' if commits != 1 else '', title, comments),
            'properties': properties,
        }

        if callable(self._codebase):
            change['codebase'] = self._codebase(payload)
        elif self._codebase is not None:
            change['codebase'] = self._codebase

        changes.append(change)

        log.msg("Received {} changes from Bitbucket PR #{}".format(
            len(changes), number))
        return changes, 'git'

    def _process_push_change(self, payload, user, repo, repo_url, project, event):
        """
        Consumes the JSON as a python object and actually starts the build.

        :arguments:
            payload
                Python Object that represents the JSON sent by Bitbucket Service
                Hook.
        """
        change_list = []

        changes = payload['changes']
        for change in changes:

            # TODO: Handle difference with hg and mercurial and other cases in :
            # https://confluence.atlassian.com/bitbucket/event-payloads-740262817.html#EventPayloads-Push
            branch = change['new']['name']
            commits = change['commits']
            for commit in commits:
                log.msg("Processing %s"%commit)
                # files = []

                when_timestamp = dateparse(commit['date'])

                log.msg("New revision: {}".format(commit['hash'][:8]))

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

                if callable(self._codebase):
                    change['codebase'] = self._codebase(payload)
                elif self._codebase is not None:
                    change['codebase'] = self._codebase

                log.msg("CHANGE:%s"%change)
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

