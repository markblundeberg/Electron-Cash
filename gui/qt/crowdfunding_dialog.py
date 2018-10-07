from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.address import Address
from electroncash.bitcoin import *
from electroncash.i18n import _

from .util import *

from electroncash.transaction import Transaction

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_crowdfunding_dialog(parent, screen_name=_("Upload Token Document")):
    d = CrowdfundingDialog(parent, screen_name)
    dialogs.append(d)
    d.show()
    return d

class CrowdfundingDialog(QDialog, MessageBoxMixin):

    def __init__(self, parent, screen_name=_("Upload Token Document")):
        # We want to be a top-level window
        QDialog.__init__(self, None)

        # check parent window type
        self.parent = parent

        self.setWindowTitle(screen_name)

        self.setMinimumSize(612, 290)

        layout = QGridLayout(self)

        self.message_e = QTextEdit()
        layout.addWidget(QLabel(_('Raw Signed Inputs (one per line)')), 1, 0)
        layout.addWidget(self.message_e, 1, 1)
        layout.setRowStretch(2,3)

        self.address_e = QLineEdit()

        self.address_e.setText("")
        layout.addWidget(QLabel(_('Destination Address')), 2, 0)
        layout.addWidget(self.address_e, 2, 1)

        self.amount_e = QLineEdit()
        layout.addWidget(QLabel(_('Amount in Satoshis')), 3, 0)
        layout.addWidget(self.amount_e, 3, 1)

        self.raw_full_tx_e = QTextEdit()
        layout.addWidget(QLabel(_('Raw Full Tx')), 4, 0)
        layout.addWidget(self.raw_full_tx_e, 4, 1)
        self.raw_full_tx_e.setReadOnly(True)

        bbox = QDialogButtonBox()
        but = bbox.addButton(_("Close"), QDialogButtonBox.RejectRole)
        but.clicked.connect(lambda: self.close())
        but = bbox.addButton(_("Build Full Tx"), QDialogButtonBox.AcceptRole)
        but.clicked.connect(lambda: self.do_sign())
        layout.addWidget(bbox, 5, 1)

    def do_sign(self):
        if Address.is_valid(self.address_e.text()):
            myaddr = Address.from_string(self.address_e.text())
        else:
            # user entered bad address
            self.show_error(_("Invalid Address"))
            return
        version = 1
        locktime = 0
        _type = 0
        try:
            myoutput = (_type, myaddr, int(self.amount_e.text()))
        except ValueError:
            self.show_error(_("Invalid Amount"))
            return
        tx = Transaction(None)
        serialized_output = tx.serialize_output(myoutput) 
        nVersion = int_to_hex(version, 4)
        nLocktime = int_to_hex(locktime, 4)
        inputs = self.message_e.toPlainText().splitlines()
        txins = var_int(len(inputs)) + ''.join(inputs)
        txouts = var_int(1) + serialized_output
        raw_tx = nVersion + txins + txouts + nLocktime 
        self.raw_full_tx_e.setText(raw_tx)
        self.raw_full_tx_e.repaint() # for some reason widget wouldn't update on macOS without this! Qt bug!

    def closeEvent(self, event):
        event.accept()
        self.parent.raise_()
        self.parent.activateWindow()
        try:
            dialogs.remove(self)
        except ValueError:
            pass

