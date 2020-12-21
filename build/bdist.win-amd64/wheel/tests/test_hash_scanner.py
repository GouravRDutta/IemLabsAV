# -*- coding: utf-8 -*-
import unittest
from iemlav.lib.antivirus.scanner.hash_scanner import HashScanner
from iemlav.lib.antivirus.scanner.virus_total import VirusTotal
from iemlav.lib.antivirus.antivirus_logger import AntiVirusLogger

try:
    # if python 3.x.x
    from unittest.mock import patch
except ImportError:  # python 2.x.x
    from mock import patch


class TestHashScanner(unittest.TestCase):
    """
    Test class for SecureTea AntiVirus Hash Scanner.
    """

    @staticmethod
    @patch.object(VirusTotal, "check_hash")
    @patch("iemlav.lib.antivirus.scanner.hash_scanner.utils")
    @patch.object(HashScanner, "check_virus_total")
    @patch.object(AntiVirusLogger, "log")
    @patch("iemlav.lib.antivirus.scanner.scanner_parent.utils")
    @patch("iemlav.lib.antivirus.scanner.hash_scanner.os")
    def test_scan_file(mck_os, mck_utils, mck_log, mck_cvt, mck_hash_utils, mck_vt):
        """
        Test scan_file.
        """
        mck_hash_utils.get_md5_hash.return_value = "md5hash"
        mck_os.listdir.return_value = ["VirusShare_1"]
        mck_hash_utils.open_file.return_value = ["md5hash"]
        mck_utils.categorize_os.return_value = "debian"
        mck_cvt.return_value = True
        mck_vt.check_hash.return_value = True
        mck_utils.json_to_dict.return_value = {
        	"debian": {
        		"update": {
        			"hash": {
        				"storage": "/etc/iemlav/antivirus/md5_hash/"
        			},
        			"yara": {
        				"storage": "/etc/iemlav/antivirus/yara/"
        			}
        		},
        		"scanner": {
        			"malicious_file_log_path": "/etc/iemlav/antivirus/malicious_files.log",
        			"hash": {
        				"threads": 2
        			},
        			"yara": {
        				"threads": 2
        			},
        			"clamav": {
        				"threads": 2
        			}
        		},
        		"monitor": {
        			"threshold_min": 20
        		}
        	}
        }

        hash_scanner_obj = HashScanner(config_path="random_path", vt_api_key="random_key")
        hash_scanner_obj.scan_file("random_path")

        mck_log.assert_called_with('File: random_path found malicious in VirusTotal Sand Box Test',
                                   logtype='warning')
