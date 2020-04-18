import pyshark
import sys
from pyshark.capture.capture import TSharkCrashException
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QLineEdit
from PyQt5.QtGui import QIcon

class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'INPUT DIALOG BOX'
        self.center = 25
        self.top = 25
        self.width = 900
        self.height = 740
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.center, self.top, self.width, self.height)      
        self.cap()
        sys.exit()

    def Get_Summaries(self):
        items = ("False", "True")
        item, okPressed = QInputDialog.getItem(self, "INPUT DIALOG BOX","Get Only_Summaries:", items, 0, False)
        if okPressed and item:
            if item == "False":
                return False
            else:
                return True
        
    def Get_Timeout(self):
        i, okPressed = QInputDialog.getInt(self, "INPUT DIALOG BOX","timeout in sec:", 1, 0, 100, 1)
        if okPressed:
            return i
        
    def Get_Choice(self):
        j, okPressed = QInputDialog.getInt(self, "INPUT DIALOG BOX","Enter 1- None\n 2-BPF filter\n 3-Display filter:", 1, 0, 100, 1)
        if okPressed:
            return j
          
    def Get_Filter(self):
        text1, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter protocol to filter:", QLineEdit.Normal, "")
        if okPressed and text1 != '':
            return text1
       
    def Get_Interface(self):
        text, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter system interface:", QLineEdit.Normal, "")
        if text is None:
            raise Exception("Interface cannot be None....\nPlease Enter Interface")
        if okPressed and text != '':
            return text

    def Get_Outputfile(self):
        text, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter filename:", QLineEdit.Normal, "")
        if "." in text:
            raise Exception("Enter filename without extension")
        if okPressed and text != '':
            return text+".pcap"

    def cap(self):
        interface_val = self.Get_Interface()
        print(interface_val)
        timeout_val = self.Get_Timeout()
        print(timeout_val)
        filename = self.Get_Outputfile()
        print(filename)
        summaries = self.Get_Summaries()
        print(type(summaries))

        value = self.Get_Choice()
        if ((value > 0) and (value <= 3)):
            if (value == 1):
              bpf_val = None
              dis_val = None
            elif (value == 2):
              bpf_val = self.Get_Filter()
              dis_val = None
            elif (value == 3):
              bpf_val = None
              dis_val = self.Get_Filter()
        else:
             raise Exception("Please Enter Valid Data!!!")
        capture = pyshark.LiveCapture(interface=interface_val, bpf_filter=bpf_val, display_filter=dis_val, only_summaries=summaries,  decryption_key=None, encryption_type='wpa-psk', output_file=filename, decode_as={'tcp.port==443':'http'})
        capture.sniff(timeout=timeout_val)
        print(capture)
        if len(capture) == 0:
            raise Exception("Please Check Internet Connectivity!!!")

if __name__ == '__main__':
        app = QApplication(sys.argv)
        ex = App()
        sys.exit(app.exec_())
