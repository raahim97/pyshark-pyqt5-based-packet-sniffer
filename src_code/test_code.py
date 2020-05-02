import unittest
from unittest.mock import Mock, patch, MagicMock

import trial
from trial import App

class TestingApp(unittest.TestCase):
    def setUp(self):
        self.setWindowTitle = Mock()
        self.setGeometry = Mock()

    def test_LiveCap(self):
        c = 1
        okpressed = True
        text1 = "wlp3s0"
        i = 30
        text2 = "capfile"
        j = 2
        text3 = "tcp"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed), (text3, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (i, okpressed), (j, okpressed)]
    
        capture = MagicMock()
        patcher = patch("trial.pyshark")
        self.addCleanup(patcher.stop)
        self.pyshark = patcher.start()
        self.pyshark.LiveCapture.return_value = capture
        capture.__len__.return_value  = 1

        self.a = App()
        self.assertEqual(self.pyshark.LiveCapture.called, True)
        self.assertEqual(capture.sniff.called, True)

    def test_noInterface(self):
        c = 1
        okpressed = True
        text1 = None
        i = 30
        text2 = "capfile"
        j = 2
        text3 = "tcp"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed), (text3, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (i, okpressed), (j, okpressed)]
        
        self.assertRaises(Exception, App)

    def test_invalidfile(self):
        c = 1
        okpressed = True
        text1 = "wlp3s0"
        i = 30
        text2 = "capfile.pcap"
        j = 2
        text3 = "tcp"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed), (text3, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (i, okpressed), (j, okpressed)]
        
        self.assertRaises(Exception, App)

    def test_invalidchoice(self):
        c = 1
        okpressed = True
        text1 = "wlp3s0"
        i = 30
        text2 = "capfile.pcap"
        j = 5
        text3 = "tcp"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed), (text3, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (i, okpressed), (j, okpressed)]
        
        self.assertRaises(Exception, App)

    def test_noInternet(self):
        c = 1
        okpressed = True
        text1 = "wlp2s0"
        i = 30
        text2 = "capfile"
        j = 2
        text3 = "tcp"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed), (text3, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (i, okpressed), (j, okpressed)]
        
        capture = MagicMock()
        patcher = patch("trial.pyshark")
        self.addCleanup(patcher.stop)
        self.pyshark = patcher.start()
        self.pyshark.LiveCapture.return_value = capture
        capture.__len__.return_value  = 0

        self.assertRaises(Exception, App)

    def test_FileCap(self):
        c = 2
        okpressed = True
        text1 = "capfile.pcap"
        a = 1
        text2 = "tcp"
        item1 = "False"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (a, okpressed)]
        self.QInputDialog.getItem.return_value = (item1, okpressed)

        capture = Mock()
        patcher = patch("trial.pyshark")
        self.addCleanup(patcher.stop)
        self.pyshark = patcher.start()
        self.pyshark.FileCapture.return_value = capture

        self.a = App()
        self.assertEqual(self.pyshark.FileCapture.called, True)
        self.assertEqual(capture.apply_on_packets.called, True)
        
    def test_Sum(self):
        c = 2
        okpressed = True
        text1 = "capfile.pcap"
        a = 1
        text2 = "tcp"
        item1 = "True"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (a, okpressed)]
        self.QInputDialog.getItem.return_value = (item1, okpressed)

        capture = Mock()
        patcher = patch("trial.pyshark")
        self.addCleanup(patcher.stop)
        self.pyshark = patcher.start()
        self.pyshark.FileCapture.return_value = capture

        self.a = App()
        self.assertEqual(self.pyshark.FileCapture.called, True)
        self.assertEqual(capture.apply_on_packets.called, True)
        
    def test_NoFilter(self):
        c = 2
        okpressed = True
        text1 = "capfile.pcap"
        a = 2
        text2 = None
        item1 = "False"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (a, okpressed)]
        self.QInputDialog.getItem.return_value = (item1, okpressed)

        capture = Mock()
        patcher = patch("trial.pyshark")
        self.addCleanup(patcher.stop)
        self.pyshark = patcher.start()
        self.pyshark.FileCapture.return_value = capture

        self.a = App()
        self.assertEqual(self.pyshark.FileCapture.called, True)
        self.assertEqual(capture.apply_on_packets.called, True)

    def test_ErrorMsg(self):
        c = 2
        okpressed = True
        text1 = "capfile.pcap"
        a = 3
        text2 = None
        item1 = "False"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (a, okpressed)]
        self.QInputDialog.getItem.return_value = (item1, okpressed)

        self.assertRaises(Exception, App)
        
    def test_invalidfile1(self):
        c = 2
        okpressed = True
        text1 = "capfile"
        a = 1
        text2 = "tcp"
        item1 = "False"

        patcher = patch("trial.QInputDialog")
        self.addCleanup(patcher.stop)
        self.QInputDialog = patcher.start()
        self.QInputDialog.getText.side_effect = [(text1, okpressed), (text2, okpressed)]
        self.QInputDialog.getInt.side_effect = [(c, okpressed), (a, okpressed)]
        self.QInputDialog.getItem.return_value = (item1, okpressed)

        self.assertRaises(Exception, App)

if __name__ == "__main__":
    unittest.main()
