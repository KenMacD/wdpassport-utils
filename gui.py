#!/usr/bin/env python

# Feel free to use edit and modify
#
# Created: Tue Jan 7 13:13:15 2013
#      by: funkypopcorn
#
# NOTE: This is my first attempt in python programing
#       pls don't judge me too hard. :)

from PyQt4 import QtCore, QtGui
import subprocess
import cookpw
import os

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

fpathc = os.path.dirname(__file__)+"/cookpw.py"
fpathp = os.path.dirname(__file__)+"/password.bin"

class Ui_Frame(object):
    def setupUi(self, Frame):
        Frame.setObjectName(_fromUtf8("Frame"))
        Frame.resize(603, 478)
        Frame.setFrameShape(QtGui.QFrame.StyledPanel)
        Frame.setFrameShadow(QtGui.QFrame.Raised)
        self.decryptBtn = QtGui.QPushButton(Frame)
        self.decryptBtn.setGeometry(QtCore.QRect(40, 190, 141, 51))
        self.decryptBtn.setObjectName(_fromUtf8("decryptBtn"))
        self.label = QtGui.QLabel(Frame)
        self.label.setGeometry(QtCore.QRect(60, 120, 65, 21))
        self.label.setObjectName(_fromUtf8("label"))
        self.label_2 = QtGui.QLabel(Frame)
        self.label_2.setGeometry(QtCore.QRect(40, 270, 121, 21))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.textEdit = QtGui.QTextEdit(Frame)
        self.textEdit.setGeometry(QtCore.QRect(40, 300, 521, 111))
        self.textEdit.setObjectName(_fromUtf8("textEdit"))
        self.label_3 = QtGui.QLabel(Frame)
        self.label_3.setGeometry(QtCore.QRect(50, 40, 511, 21))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Waree"))
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setLineWidth(1)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.pwBox = QtGui.QTextEdit(Frame)
        self.pwBox.setGeometry(QtCore.QRect(140, 120, 381, 31))
        self.pwBox.setObjectName(_fromUtf8("pwBox"))
        self.exitBtn = QtGui.QPushButton(Frame)
        self.exitBtn.setGeometry(QtCore.QRect(390, 190, 151, 51))
        self.exitBtn.setObjectName(_fromUtf8("exitBtn"))
        self.mountBtn = QtGui.QPushButton(Frame)
        self.mountBtn.setEnabled(False)
        self.mountBtn.setGeometry(QtCore.QRect(210, 190, 151, 51))
        self.mountBtn.setObjectName(_fromUtf8("mountBtn"))
        self.label_4 = QtGui.QLabel(Frame)
        self.label_4.setGeometry(QtCore.QRect(50, 420, 541, 41))
        self.label_4.setObjectName(_fromUtf8("label_4"))

        self.retranslateUi(Frame)
        QtCore.QObject.connect(self.exitBtn, QtCore.SIGNAL(_fromUtf8("clicked()")), Frame.close)
        QtCore.QObject.connect(self.decryptBtn, QtCore.SIGNAL(_fromUtf8("clicked()")), self.decryptWD)
        QtCore.QObject.connect(self.mountBtn, QtCore.SIGNAL(_fromUtf8("clicked()")), self.mountWD)
        QtCore.QMetaObject.connectSlotsByName(Frame)

    def retranslateUi(self, Frame):
        Frame.setWindowTitle(_translate("Frame", "WD-Decrypt", None))
        self.decryptBtn.setText(_translate("Frame", "decrypt HDD", None))
        self.label.setText(_translate("Frame", "Password:", None))
        self.label_2.setText(_translate("Frame", "Status/Error-Log:", None))
        self.label_3.setText(_translate("Frame", "Unofficial WD Decrypt Linux Mounter", None))
        self.exitBtn.setText(_translate("Frame", "Exit", None))
        self.mountBtn.setText(_translate("Frame", "mount HDD", None))
        self.label_4.setText(_translate("Frame", "<html><head/><body><p><span style=\" font-size:10pt; font-style:italic;\">(Please disconnect and reconnect the WD harddrive just before using this program. <br/>Otherwise it will not recognize the harddrive properly!)</span></p></body></html>", None))


    def decryptWD(self):
        try:
            subprocess.check_call("command -v sg_raw >/dev/null 2>&1", shell=True)
            self.callCookingPW()
        except subprocess.CalledProcessError:
            self.textEdit.setText("sg3-utils not installed, so we are going to install it...")
            try:
                subprocess.check_call("gksudo apt-get install sg3-utils", shell=True)
            except subprocess.CalledProcessError:
                self.textEdit.append("Installation went wrong! You have to install/compile it manually sorry!")
                return
            self.textEdit.append("sg3-utils installed successfully!")
            self.callCookingPW()


    def callCookingPW(self):
        self.textEdit.append("Calling external cookpw-script...")
        app.processEvents()
        try:
            pw = str(self.pwBox.toPlainText())
            if not pw == "":
                fpathc = os.path.dirname(__file__)+"/cookpw.py"
                subprocess.check_call("python "+fpathc+" "+pw+" >"+fpathp, shell=True)
            else:
                self.textEdit.append("Password left empty pls type in PW and click Mount again!")
                return
        except subprocess.CalledProcessError:       
            self.textEdit.append("Script calling went wrong, pls check if the path to cookpw.py is correct!")
            return
        try:
            with open(fpathp):
                self.textEdit.append("Sending SCSI commands to encrypt/unlock the drive...")
                self.unlockDrive()
        except IOError:
            self.textEdit.append("Something went wrong while executing cookpw.py -> password.bin not created!")
            return
        

    def unlockDrive(self):
        try:
            from subprocess import check_output as qx
            out = qx("/bin/dmesg | grep sg | grep \"type 13\" | awk \'{print $8}\'",shell=True)
            #check if there is only one unique sg device otherwise stop
            try:
                cmp = out.split( )[0]
            except IndexError:
                self.textEdit.append("Couldn't find WD Drive in dmesg, pls unplug and replug the drive again!")
                return
            multipleDevices = False;
            for word in out.split( ):
                if not cmp==word:
                   multipleDevices = True
                   break
            if not multipleDevices:
                #finally lets send the SCSI command to encrypt
                self.textEdit.append("Secure Harddrive identified at /dev/"+cmp)
                try:
                    subprocess.check_call("gksudo whoami", shell=True)
                    subprocess.check_call("sudo sg_raw -s 40 -i "+fpathp+" /dev/"+cmp+" c1 e1 00 00 00 00 00 00 28 00", shell=True)
                    self.textEdit.append("Drive is now unlogged and can be mounted!")
                    self.mountBtn.setEnabled(True)
                except subprocess.CalledProcessError:
                    self.textEdit.append("Failure while sending SCSI encrypt command -> Check if harddrive is connected properly! (Maybe /dev/"+cmp+" does not exist)")
                    return
            else:
                self.textEdit.append("Failure multiple SCSI type 13 devices recognized pls unplug everything except the WD drive and wait a bit before you retry.")
                return
        except subprocess.CalledProcessError:
            self.textEdit.append("Failure couldn't find sg type within dmesg!")
            return


    def mountWD(self):
        self.decryptBtn.setEnabled(False)
        try:
            subprocess.check_call("command -v partprobe >/dev/null 2>&1", shell=True)
            self.autoMount()
        except subprocess.CalledProcessError:
            self.textEdit.setText("parted not installed, so we are going to install it...")
            try:
                subprocess.check_call("gksudo apt-get install parted", shell=True)
            except subprocess.CalledProcessError:
                self.textEdit.append("Installation went wrong! You have to install/compile parted manually sorry!")
                return
            self.textEdit.append("Parted installed successfully!")
            self.autoMount()


    def autoMount(self):
        try:
            subprocess.check_call("gksudo whoami", shell=True)
            subprocess.call("sudo partprobe", shell=True)
            self.textEdit.setText("Available devices have been updated!")
            try:
                subprocess.check_call("/usr/bin/udisks --mount /dev/sdb1", shell=True)
                self.textEdit.setText("WD Harddrive encrypted and mounted successfully!")
                return
            except subprocess.CalledProcessError:
                self.textEdit.setText("Failure: udisk automoint didn't work! Maybe the uuid/Volume Serial Number you entered is wrong!")
                return
        except subprocess.CalledProcessError:
            self.textEdit.setText("Failure: partprobe not successfull -> check path to partprobe (which partprobe)")
            return



if __name__ == "__main__":
    import sys
    global app
    app = QtGui.QApplication(sys.argv)
    Frame = QtGui.QFrame()    
    ui = Ui_Frame()
    ui.setupUi(Frame)
    Frame.show()
    sys.exit(app.exec_())
