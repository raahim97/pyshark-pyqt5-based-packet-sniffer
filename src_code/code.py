import pyshark
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QInputDialog, QLineEdit
from PyQt5.QtGui import QIcon

app = QApplication(sys.argv)

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
        choice = self.Get_CaptureChoice()
        if choice == 1:
            self.Live_Cap()
        elif choice == 2:
            self.File_Cap()
        else:
            raise Exception("Please Enter Valid Data!!!")
        #sys.exit()

    def Get_CaptureChoice(self):
        c, okPressed = QInputDialog.getInt(self, "INPUT DIALOG BOX","Enter 1- LiveCapture:\n 2- FileCapture:", 1, 0, 100, 1)
        if okPressed:
            return c

    def Get_Filter(self):
        text, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter protocol to filter:", QLineEdit.Normal, "")
        if okPressed and text != '':
            return text

    def Get_FilterChoice(self):
        j, okPressed = QInputDialog.getInt(self, "INPUT DIALOG BOX","Enter 1- None\n 2-BPF filter\n 3-Display filter:", 1, 0, 100, 1)
        if okPressed:
            return j

    def Get_Outputfile(self):
        text, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter filename:", QLineEdit.Normal, "")
        if "." in text:
            raise Exception("Enter filename without extension")
        if okPressed and text != '':
            return text+".pcap"

    def Get_Timeout(self):
        i, okPressed = QInputDialog.getInt(self, "INPUT DIALOG BOX","timeout in sec:", 1, 0, 100, 1)
        if okPressed:
            return i

    def Get_Interface(self):
        text, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter system interface:", QLineEdit.Normal, "")
        if text is None:
            raise Exception("Interface cannot be None....\nPlease Enter Interface")
        if okPressed and text != '':
            return text

    def Live_Cap(self):
        interface_val = self.Get_Interface()
        #print(interface_val)
        timeout_val = self.Get_Timeout()
        #print(timeout_val)
        filename = self.Get_Outputfile()
        #print(filename)
        value = self.Get_FilterChoice()
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
        capture = pyshark.LiveCapture(interface=interface_val, bpf_filter=bpf_val, display_filter=dis_val, decryption_key=None, encryption_type='wpa-psk', output_file=filename, decode_as={'tcp.port==443':'http'})
        capture.sniff(timeout=timeout_val)
        #print(capture)
        if len(capture) == 0:
            raise Exception("Please Check Internet Connectivity and your Interface!!!")

    def Get_Summaries(self):
        items = ("False", "True")
        item, okPressed = QInputDialog.getItem(self, "INPUT DIALOG BOX","Get Only_Summaries:", items, 0, False)
        if okPressed and item:
            if item == "False":
                return False
            else:
                return True
            
    def Get_Choice(self):
        j, okPressed = QInputDialog.getInt(self, "INPUT DIALOG BOX","Press\n 1 - Get desired filter\n 2 - Get all the filters", 1, 0, 100, 1)
        if okPressed:
            return j
        
    def Get_Inputfile(self):
        text, okPressed = QInputDialog.getText(self, "INPUT DIALOG BOX","Enter filename with extension:", QLineEdit.Normal, "")
        if not ".pcap" in text:
            raise Exception("Enter a filename with .pcap extension")
        if okPressed and text != '':
            return text

    def print_packet_info(self, packet):
        print(packet)

    def File_Cap(self):
        inputfile_val = self.Get_Inputfile()
        #print(inputfile_val)
        choice_val = self.Get_Choice()
        #print(choice_val)
        if choice_val == 1:
          filter_val = self.Get_Filter()
          #print(filter_val)
        elif choice_val == 2:
          filter_val = None
        else:
          raise Exception("Please Enter Valid Data!!!")
        summaries = self.Get_Summaries()
        #print(summaries)

        capture = pyshark.FileCapture(input_file=inputfile_val, display_filter=filter_val, only_summaries=summaries)
        capture.apply_on_packets(self.print_packet_info)

if __name__ == '__main__':
        ex = App()
        sys.exit(app.exec_())
