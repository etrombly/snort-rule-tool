#!/usr/bin/env python2

import sys
from PyQt5 import QtWidgets
from mainwindow import Ui_MainWindow
from scapy.all import *

""" dump any string, ascii or encoded, to formatted hex output """
def dumpString(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    result = []
    for i in xrange(0, len(src), length):
       chars = src[i:i+length]
       hex = ' '.join(["%02x" % ord(x) for x in chars])
       printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
       result.append(["%04x" % (i,), "%-*s" % (length*3, hex), "%s" % (printable,)])
    return result

class Snort(QtWidgets.QMainWindow):
    def __init__(self):
        super(Snort, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.show()
        self.index = 0
        self.ui.packetBox.valueChanged.connect(self.changePacket)
        self.ui.actionOpen.triggered.connect(self.openPCAP)

    def changePacket(self):
        self.index = self.ui.packetBox.value() - 1
        self.readPacket()

    def readPacket(self):
        self.clearAll()
        pkt = self.packets[self.index]
        test = dumpString(str(pkt))
        for line in test:
            self.ui.lineColumn.appendPlainText(line[0])
            self.ui.hexColumn.appendPlainText(line[1])
            self.ui.textColumn.appendPlainText(line[2])
        if IP in pkt:
            self.ui.protoCombo.setCurrentText("ip")
            self.ui.srcCombo.insertItem(0, pkt[IP].src)
            self.ui.destCombo.insertItem(0,pkt[IP].dst)
        if IPv6 in pkt:
                self.ui.protoCombo.setCurrentText("ip")
                self.ui.srcCombo.insertItem(0, pkt[IPv6].src)
                self.ui.destCombo.insertItem(0,pkt[IPv6].dst)
        if TCP in pkt:
            self.ui.protoCombo.setCurrentText("tcp")
            self.ui.srcPortCombo.insertItem(0, str(pkt[TCP].sport))
            self.ui.destPortCombo.insertItem(0, str(pkt[TCP].dport))
        if UDP in pkt:
            self.ui.protoCombo.setCurrentText("udp")
            self.ui.srcPortCombo.insertItem(0, str(pkt[UDP].sport))
            self.ui.destPortCombo.insertItem(0, str(pkt[UDP].dport))
        if ICMP in pkt:
            self.ui.protoCombo.setCurrentText("icmp")
        for combo in self.comboBoxes:
            combo.setCurrentIndex(0)
        self.ui.ruleText.appendPlainText(self.buildRule())

    def openPCAP(self):
        filename = QtWidgets.QFileDialog.getOpenFileName(self, 'Open PCAP',filter='Packet Captures (*.cap *.pcap)')
        if filename:
            self.file = filename[0]
            self.packets = rdpcap(self.file)
            self.comboBoxes = [self.ui.srcCombo, self.ui.srcPortCombo, self.ui.destCombo, self.ui.destPortCombo]
            self.ui.packetBox.setRange(1, len(self.packets))
            self.readPacket()

    def clearAll(self):
        for combo in self.comboBoxes:
            combo.clear()
            combo.addItem("any")
        self.ui.destPortCombo.addItem("any")
        self.ui.lineColumn.clear()
        self.ui.hexColumn.clear()
        self.ui.textColumn.clear()
        self.ui.ruleText.clear()

    def buildRule(self):
        rule = "%s %s %s %s %s %s %s {msg: 'placeholder text'; sid: 1000000}" % (
                        self.ui.actionCombo.currentText(),
                        self.ui.protoCombo.currentText(),
                        self.ui.srcCombo.currentText(),
                        self.ui.srcPortCombo.currentText(),
                        self.ui.dirCombo.currentText(),
                        self.ui.destCombo.currentText(),
                        self.ui.destPortCombo.currentText())
        return rule

def main():
    app = QtWidgets.QApplication(sys.argv)
    snort = Snort()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
