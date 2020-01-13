#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from functools import wraps
from sqlite3 import connect
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['api'] = MagicMock()
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        def RBAC_bypasser(**kwargs):
            def decorator(f):
                @wraps(f)
                def wrapper(*args, **kwargs):
                    return f(*args, **kwargs)

                return wrapper
            return decorator

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.ciscat import get_ciscat_results
        from wazuh.results import AffectedItemsWazuhResult


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
agents_info = ['001', '002']


# Get a fake database
def get_fake_syscheck_db(sql_file):
    def create_memory_db(*args, **kwargs):
        syscheck_db = connect(':memory:')
        cur = syscheck_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())
        return syscheck_db

    return create_memory_db


@pytest.mark.parametrize('agent_id', [
    ['001']
])
@patch('wazuh.ciscat.get_agents_info', return_value=agents_info)
@patch('sqlite3.connect', side_effect=get_fake_syscheck_db('schema_ciscat_test.sql'))
@patch('socket.socket.connect')
def test_get_ciscat_agent(socket_mock, db_mock, agents_info_mock, agent_id):
    result = get_ciscat_results(agent_id)
    assert isinstance(result, AffectedItemsWazuhResult)
