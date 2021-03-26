import pytest
from pathlib import Path
import logging
import os
from libs.log_request import LogRequest
from libs.logging import setup_logging
from libs.config import find_config_dir, set_profile, set_root_dir

class TestLogging():
    def test_setup(self):
        cfg_dir = Path(find_config_dir())
        set_profile('test')
        log_dir = Path(cfg_dir.parents[0], 'logs1')
        log_dir.mkdir(exist_ok=True)
        os.environ["logdir"] = str(log_dir)
        setup_logging(str(cfg_dir), 256, 256, 5)
        logger = logging.getLogger('synapse')

    def test_http_request(self):
        """Test generating a HTTP request log"""
        request_headers = {
            'header1': "testing1",
            'Host': "www.example.com",
            'X-User': '{"userId": 1000, "email":  "george@example.com"}',
            'X-TranactionId': '0AXB9V5GUdg8m4om10jCMeUr'
        }
        logger = logging.getLogger('synapse')
        request_status = 200
        lrq = LogRequest(logging.getLogger('synapse'))
#        result = lrq.log(request_headers, 'POST', '/synapse/src/v1', request_status, 1000, usrctx)

    def test_log_dir_not_exist(self):
        cfg_dir = Path(find_config_dir())
        setup_logging(str(cfg_dir), 256, 256, 5)
        logger = logging.getLogger('synapse')

    def test_log_dir_permissions_error(self):
        cfg_dir = Path(find_config_dir())
        log_dir = Path(cfg_dir.parents[0], 'logs2')
        log_dir.mkdir(mode=0o444, exist_ok=True)
        os.environ["logdir"] = str(log_dir)
        setup_logging(str(cfg_dir), 256, 256, 5)
        logger = logging.getLogger('synapse')
        logger.info('Message')

    def test_rollover(self):
        cfg_dir = Path(find_config_dir())
        log_dir = Path(cfg_dir.parents[0], 'logs3')
        log_dir.mkdir(exist_ok=True)
        os.environ["logdir"] = str(log_dir)
        setup_logging(str(cfg_dir), 256, 256, 5)
        logger = logging.getLogger('synapse')
        for i in range(256):
            logger.info('Message %d', i)
            logger.error('Message %d', i)

        for i in range(1,6):
            sel = Path(log_dir, 'synapse-error.log.{}'.format(i))
            assert sel.exists()
            scl = Path(log_dir, 'synapse-combined.log.{}'.format(i))
            assert scl.exists()
