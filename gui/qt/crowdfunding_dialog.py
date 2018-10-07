import copy
import datetime
import time
from functools import partial
import json
import threading
import sys
from pathlib import Path
from os.path import basename, splitext

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.address import Address, PublicKey, Base58Error
from electroncash.bitcoin import *
from electroncash.i18n import _
from electroncash.plugins import run_hook

from .util import *

from electroncash.util import bfh,   NotEnoughFunds, ExcessiveFee, InvalidPassword
from electroncash.transaction import Transaction

from .transaction_dialog import show_transaction

dialogs = []  # Otherwise python randomly garbage collects the dialogs...


class CrowdfundingDialog(QDialog, MessageBoxMixin):

    def __init__(self, parent, file_receiver=None, show_on_create=False, screen_name="Upload Token Document"):
        # We want to be a top-level window
        QDialog.__init__(self, parent)

        # check parent window type
        self.parent = parent
        from .main_window import ElectrumWindow

        self.setWindowTitle(_(screen_name))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel("Create Crowdfunding Transaction"))

        d = WindowModalDialog(self, _('Crowdfunding Transaction'))
        d.setMinimumSize(610, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        layout.addWidget(QLabel(_('Raw Signed Inputs (one per line)')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        #address_e.setText(address.to_ui_string() if address else '')

        address_e.setText("")
        layout.addWidget(QLabel(_('Destination Address')), 2, 0)
        layout.addWidget(address_e, 2, 1)

        amount_e = QLineEdit()
        layout.addWidget(QLabel(_('Amount in Satoshis')), 3, 0)
        layout.addWidget(amount_e, 3, 1)

        raw_full_tx_e = QTextEdit()
        layout.addWidget(QLabel(_('Raw Full Tx')), 4, 0)
        layout.addWidget(raw_full_tx_e, 4, 1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Build Full Tx"))
        b.clicked.connect(lambda: self.do_sign(address_e, message_e, amount_e,raw_full_tx_e))
        hbox.addWidget(b)



        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 5, 1)
        d.exec_()


    def do_sign(self,address_e, message_e, amount_e,raw_full_tx_e):

        version = 1
        locktime=0
        tx=Transaction("")
        _type= 0
        myaddr=Address.from_string(address_e.text())
        myoutput = (_type, myaddr, int(amount_e.text())) 
        serialized_output=Transaction.serialize_output(tx, myoutput) 
        nVersion = int_to_hex(version, 4)
        nLocktime = int_to_hex(locktime, 4)
        inputs = message_e.toPlainText().splitlines()
        txins = var_int(len(inputs)) + ''.join(inputs)
        txouts = var_int(1) + serialized_output
        raw_tx = nVersion + txins + txouts + nLocktime 
        raw_full_tx_e.setText(raw_tx)

     

    def closeEvent(self, event):
        event.accept()
        self.parent.raise_()
        self.parent.activateWindow()
        try:
            dialogs.remove(self)
        except ValueError:
            pass
