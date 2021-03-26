import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter
import json
import os
from pathlib import Path
import sys
from libs.config import get_config, set_root_dir

class JsonFormatter(Formatter):
    def format(self, record):
        assert isinstance(record, logging.LogRecord)
        try:
            my_msg = ''
            if not record.exc_info:
                if record.args:
                    my_msg = (record.msg % record.args)
                else:
                    my_msg = record.msg
            else:
                # Cache the traceback text to avoid converting it multiple times
                # (it's constant anyway)
                if not record.exc_text:
                    record.exc_text = self.formatException(record.exc_info)
                if record.exc_text:
                    if my_msg[-1:] != '\n':
                        my_msg = my_msg + '\n'
                    my_msg = my_msg + record.exc_text
                if record.stack_info:
                    if my_msg[-1:] != '\n':
                        my_msg = my_msg + '\n'
                    my_msg = my_msg + self.formatStack(record.stack_info)

            obj = {'message': my_msg, 'level': record.levelname, 'timestamp': self.formatTime(record)}
            extra_fields = ('email', 'txid', 'userId')
            #rec_vars = record.__dict__.keys()
            for fn in extra_fields:
                if hasattr(record, fn):
                    obj[fn] = getattr(record, fn)
            return json.dumps(obj)
        except Exception as e:
            print('JsonFormatter exception', file=sys.stderr)
            print(e, file=sys.stderr)
            return 'JsonFormatter exception {}'.format(e)

def can_write_log(log_dir):
    """Determine if a file can be written to log_dir"""
    msg = None
    if log_dir.exists():
        fn = Path(log_dir, 'test.log')
        try:
            fn.write_text('data')
            fn.unlink()
        except Exception as e:
            msg = str(e)
    else:
        msg = '%s (No directory)' % str(log_dir)
    return msg

def setup_logging(config_dir='', error_file_max=10485760, combined_file_max=16777216, backup_count=10):
    """Setup the logging configuration"""
    profile = os.getenv('PY_ENV', 'production')
    if config_dir:
        set_root_dir(config_dir)
    the_level = get_config('loglevel') if not None else logging.INFO
    the_dir = Path(get_config('logdir'))
    if not the_dir.is_absolute():
        the_dir = the_dir.resolve()

    logger = logging.getLogger('synapse')
    logger.propagate = False
    logger.setLevel(the_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    emsg = can_write_log(the_dir)
    if not emsg:
        the_path = Path(the_dir, 'synapse-combined.log')
        rfh = RotatingFileHandler(str(the_path), maxBytes=combined_file_max, backupCount=backup_count)
        rfh.setFormatter(JsonFormatter())
        logger.addHandler(rfh)

        the_path = Path(the_dir, 'synapse-error.log')
        rfh = RotatingFileHandler(str(the_path), maxBytes=error_file_max, backupCount=backup_count)
        rfh.setFormatter(JsonFormatter())
        rfh.setLevel(logging.ERROR)
        logger.addHandler(rfh)

        if profile == 'development':
            console = logging.StreamHandler()
            console.setLevel(logging.DEBUG)
            console.setFormatter(formatter)
            logger.addHandler(console)

        logging.getLogger().setLevel('ERROR')
    else:
        print('Error: Cannot open logging directory (%s)' % emsg)
        console = logging.StreamHandler()
        console.setLevel(the_level)
        console.setFormatter(formatter)
        logger.addHandler(console)
