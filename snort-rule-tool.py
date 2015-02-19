#!/usr/bin/env python2

import sys
from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import QtCore
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
       result.append(["%-*s" % (length*3, hex), "%s" % (printable,)])
    return result

class Snort(QtWidgets.QMainWindow):
    def __init__(self):
        super(Snort, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.show()
        self.index = 0
        self.defaultFmt = self.ui.hexColumn.currentCharFormat()
        self.ui.packetBox.valueChanged.connect(self.changePacket)
        self.ui.actionOpen.triggered.connect(self.openPCAP)
        self.ui.contentEdit.textChanged.connect(self.contentChanged)
        self.ui.flowCheck.stateChanged.connect(self.flowChecked)
        self.ui.streamButton.clicked.connect(self.assembleStream)
        self.ui.flowCombo.currentTextChanged.connect(self.buildRule)
        self.ui.protoCombo.currentTextChanged.connect(self.buildRule)
        self.ui.srcCombo.currentTextChanged.connect(self.buildRule)
        self.ui.srcPortCombo.currentTextChanged.connect(self.buildRule)
        self.ui.dirCombo.currentTextChanged.connect(self.buildRule)
        self.ui.destCombo.currentTextChanged.connect(self.buildRule)
        self.ui.destPortCombo.currentTextChanged.connect(self.buildRule)
        self.streams = []

    def changePacket(self):
        self.index = self.ui.packetBox.value() - 1
        self.readPacket()

    def findStreams(self):
        tcp_streams = self.packets.filter(lambda p: p.haslayer(TCP))
        self.streams = []

        for syn in tcp_streams.filter(lambda p: p[TCP].flags & 0x02):
            for synack in tcp_streams.filter(lambda p: p[TCP].flags & 0x12 and p[TCP].ack == syn.seq + 1):
                ack = tcp_streams.filter(lambda p: p[TCP].flags & 0x10 and p[TCP].ack == synack.seq + 1)
                if ack:
                    srcport = syn[TCP].sport
                    dstport = syn[TCP].dport
                    L3 = IP
                    try:
                        #try underlayer
                        foot = syn[TCP].underlayer
                        srcip = foot.src
                        dstip = foot.dst
                        if type(foot) == IPv6:
                            L3 = IPv6
                    except:
                        #try other, but upper layer
                        if IPv6 in syn:
                            srcip = syn[IPv6].src
                            dstip = syn[IPv6].dst
                            L3 = IPv6
                        elif IP in pkt:
                            srcip = syn[IP].src
                            dstip = syn[IP].dst
                        else:
                            continue
                    ip_pair = (srcip,dstip)
                    port_pair = (srcport,dstport)
                    filtered_stream = tcp_streams.filter(lambda p: p[TCP].dport in port_pair and \
                                                                   p[TCP].sport in port_pair and \
                                                                   p[L3].src in ip_pair and \
                                                                   p[L3].dst in ip_pair)
                    assembled_stream = [syn,synack,ack[0]]
                    while True:
                        client_next_seq = assembled_stream[-1][TCP].seq
                        server_next_seq = assembled_stream[-1][TCP].ack
                        next = filtered_stream.filter(lambda p: p.seq in (client_next_seq,server_next_seq) and \
                                                                not p in assembled_stream)
                        if not next:
                            break
                        for pkt in next:
                            assembled_stream.append(pkt)
                    self.streams.append(PacketList(assembled_stream))

    def assembleStream(self):
        pkt = self.packets[self.index]
        self.ui.hexColumn.clear()
        self.ui.textColumn.clear()
        for stream in self.streams:
            if pkt in stream:
                thisStream = stream
                break
        streamText = "".join([str(packet) for packet in thisStream])
        payload = dumpString(streamText)
        for line in payload:
            self.ui.hexColumn.appendPlainText(line[0])
            self.ui.textColumn.appendPlainText(line[1])

    def readPacket(self):
        self.clearAll()
        pkt = self.packets[self.index]
        payload = dumpString(str(pkt))
        for line in payload:
            self.ui.hexColumn.appendPlainText(line[0])
            self.ui.textColumn.appendPlainText(line[1])
        if IP in pkt:
            self.ui.protoCombo.setCurrentText("ip")
            self.ui.srcCombo.insertItem(0, pkt[IP].src)
            self.ui.destCombo.insertItem(0,pkt[IP].dst)
            srcip = pkt[IP].src
        if IPv6 in pkt:
                self.ui.protoCombo.setCurrentText("ip")
                self.ui.srcCombo.insertItem(0, pkt[IPv6].src)
                self.ui.destCombo.insertItem(0,pkt[IPv6].dst)
                srcip = pkt[IPv6].src
        if TCP in pkt:
            self.ui.protoCombo.setCurrentText("tcp")
            self.ui.srcPortCombo.insertItem(0, str(pkt[TCP].sport))
            self.ui.destPortCombo.insertItem(0, str(pkt[TCP].dport))
            for stream in self.streams:
                if pkt in stream:
                    self.ui.flowCheck.setChecked(True)
                    self.ui.streamButton.setEnabled(True)
                    client = stream[0]
                    if IP in client:
                        layer = IP
                    else:
                        layer = IPv6
                    if srcip == client[layer].src:
                        self.ui.flowCombo.setCurrentText("to_server")
                    elif srcip == client[layer].dst:
                        self.ui.flowCombo.setCurrentText("to_client")

        if UDP in pkt:
            self.ui.protoCombo.setCurrentText("udp")
            self.ui.srcPortCombo.insertItem(0, str(pkt[UDP].sport))
            self.ui.destPortCombo.insertItem(0, str(pkt[UDP].dport))
        if ICMP in pkt:
            self.ui.protoCombo.setCurrentText("icmp")
        for combo in self.comboBoxes:
            combo.setCurrentIndex(0)
        self.buildRule()

    def openPCAP(self):
        filename = QtWidgets.QFileDialog.getOpenFileName(self, 'Open PCAP',filter='Packet Captures (*.cap *.pcap)')
        if filename:
            self.file = filename[0]
            self.packets = rdpcap(self.file)
            self.findStreams()
            self.comboBoxes = [self.ui.srcCombo, self.ui.srcPortCombo, self.ui.destCombo, self.ui.destPortCombo]
            self.ui.packetBox.setRange(1, len(self.packets))
            self.readPacket()

    def contentChanged(self):
        content = self.ui.contentEdit.text()
        hexContent = self.ui.hexColumn.toPlainText()
        cursor = QtGui.QTextCursor(self.ui.hexColumn.document())
        cursor.setPosition(0, QtGui.QTextCursor.MoveAnchor)
        cursor.setPosition(self.ui.hexColumn.document().characterCount() - 1, QtGui.QTextCursor.KeepAnchor)
        cursor.setCharFormat(self.defaultFmt)
        if content in hexContent:
            start = hexContent.index(content)
            end = len(content) + start
            fmt = QtGui.QTextCharFormat()
            fmt.setForeground(QtCore.Qt.red)
            cursor.setPosition(start, QtGui.QTextCursor.MoveAnchor)
            cursor.setPosition(end, QtGui.QTextCursor.KeepAnchor)
            cursor.setCharFormat(fmt)

    def clearAll(self):
        for combo in self.comboBoxes:
            combo.clear()
            combo.addItem("any")
        self.ui.destPortCombo.addItem("any")
        self.ui.hexColumn.clear()
        self.ui.textColumn.clear()
        self.ui.ruleText.clear()
        self.ui.contentEdit.clear()
        self.ui.flowCheck.setChecked(False)
        self.ui.flowCombo.setCurrentText("established")
        self.ui.flowCombo.setEnabled(False)
        self.ui.streamButton.setEnabled(False)

    def flowChecked(self):
        self.ui.flowCombo.setEnabled(self.ui.flowCheck.isChecked())
        self.buildRule()

    def buildRule(self):
        self.ui.ruleText.clear()
        options = ""
        if self.ui.flowCheck.isChecked():
            options += "flow: %s;" % (self.ui.flowCombo.currentText(), )
        rule = "%s %s %s %s %s %s %s {%s}" % (
                        self.ui.actionCombo.currentText(),
                        self.ui.protoCombo.currentText(),
                        self.ui.srcCombo.currentText(),
                        self.ui.srcPortCombo.currentText(),
                        self.ui.dirCombo.currentText(),
                        self.ui.destCombo.currentText(),
                        self.ui.destPortCombo.currentText(),
                        options)
        self.ui.ruleText.appendPlainText(rule)

def main():
    app = QtWidgets.QApplication(sys.argv)
    snort = Snort()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
