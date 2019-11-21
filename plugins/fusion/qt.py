#!/usr/bin/env python3
import time
from functools import partial
import weakref
import threading

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash.plugins import hook
from electroncash.i18n import _, ngettext, pgettext
from electroncash.util import print_error, profiler, PrintError, Weak, format_satoshis_plain, finalization_print_error, InvalidPassword
from electroncash_gui.qt.util import EnterButton, CancelButton, Buttons, CloseButton, HelpLabel, OkButton, rate_limited, AppModalDialog, WaitingDialog
from electroncash_gui.qt.main_window import StatusBarButton

from .fusion import can_fuse_from, can_fuse_to, DEFAULT_SELF_FUSE
from .server import FusionServer, Params
from .plugin import FusionPlugin, TOR_PORTS, is_tor_port, server_list, get_upnp, DEFAULT_SELECTOR, COIN_FRACTION_FUDGE_FACTOR, select_coins

from pathlib import Path
heredir = Path(__file__).parent
icon_fusion_logo = QIcon(str(heredir / 'Cash Fusion Logo - No Text.svg'))
icon_fusion_logo_gray = QIcon(str(heredir / 'Cash Fusion Logo - No Text Gray.svg'))

class Plugin(FusionPlugin):
    utilwin = None
    settingswin = None
    initted = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs) # gives us self.config
        self.widgets = weakref.WeakSet() # widgets we made, that need to be hidden & deleted when plugin is disabled

    def on_close(self):
        super().on_close()
        # Shut down plugin.
        # This can be triggered from one wallet's window while
        # other wallets' windows have plugin-related modals open.
        self.active = False
        # TODO: disable auto-fusing
        for window in self.gui.windows:
            # this could be slow since it touches windows one by one... could optimize this by dispatching simultaneously.
            self.on_close_window(window)
        self.utilwin = None
        self.settingswin = None
        # Clean up
        for w in self.widgets:
            try:
                w.setParent(None)
                w.close()
                w.hide()
                w.deleteLater()
            except Exception:
                # could be <RuntimeError: wrapped C/C++ object of type SettingsDialog has been deleted> but really we just want to suppress all exceptions
                pass

    @hook
    def init_qt(self, gui):
        # This gets called when this plugin is initialized, but also when
        # any other plugin is initialized after us.
        if self.initted:
            return
        self.initted = True
        self.gui = gui

        # We also have to find which windows are already open, and make
        # them work with fusion.
        for window in self.gui.windows:
            self.on_new_window(window)

    @hook
    def address_list_context_menu_setup(self, address_list, menu, addrs):
        if not self.active:
            return
        wallet = address_list.wallet
        network = wallet.network
        if not (can_fuse_from(wallet) and can_fuse_to(wallet) and network):
            return
        if not hasattr(wallet, '_fusions'):
            # that's a bug... all wallets should have this
            return

        coins = wallet.get_utxos(addrs, exclude_frozen=True, mature=True, confirmed_only=True, exclude_slp=True)

        def start_fusion():
            password = None
            error = ''
            if wallet.has_password():
                while True:
                    msg = '\n'.join([error,_("Enter your password to fuse these coins")])
                    password = address_list.parent.password_dialog(msg)
                    if password is None: # cancelled
                        return
                    try:
                        wallet.check_password(password)
                        break
                    except Exception as e:
                        error = str(e)

            with wallet.lock:
                if not hasattr(wallet, '_fusions'):
                    return
                try:
                    fusion = self.start_fusion(wallet, password, coins)
                except RuntimeError as e:
                    QMessageBox.critical(address_list, 'Error', _('CashFusion failed: %(err)s')%dict(err=str(e)))
                    return

        if coins:
            menu.addAction(ngettext("Input one coin to CashFusion", "Input %(count)d coins to CashFusion", len(coins)) % dict(count = len(coins)),
                           start_fusion)

    @hook
    def on_new_window(self, window):
        # Called on initial plugin load (if enabled) and every new window; only once per window.
        wallet = window.wallet
        # bit of a dirty hack, to insert our status bar icon (always using index 4, should put us just after the password-changer icon)
        sb = window.statusBar()

        want_autofuse = wallet.storage.get('cashfusion_autofuse', False)
        self.add_wallet(wallet)

        if want_autofuse and not self.is_autofusing(wallet):
            def callback(password):
                self.enable_autofusing(wallet, password)
                button = window._cashfusion_button()
                button.update_state()
            d = PasswordDialog(window, wallet, _("Previously you had auto-Fusion enabled on this wallet. If you would like to keep automatic fusing in background, enter your password."),
                               callback_ok = callback)
            d.show()
            self.widgets.add(d)

        sbbtn = FusionButton(self, wallet)
        sb.insertPermanentWidget(4, sbbtn)
        self.widgets.add(sbbtn)
        window._cashfusion_button = weakref.ref(sbbtn)

    @hook
    def on_close_window(self, window):
        # Invoked when closing wallet or entire application
        # Also called by on_close, above.
        wallet = window.wallet

        fusions = self.remove_wallet(wallet)
        if not fusions:
            return

        for f in fusions:
            f.stop('Closing wallet')

        # Soft-stop background fuse if running.
        # We avoid doing a hard disconnect in the middle of a fusion round.
        def task():
            for f in fusions:
                f.join()
        d = WaitingDialog(window, _('Shutting down active CashFusions (may take a minute to finish)'), task)
        d.exec_()

    @hook
    def on_new_password(self, window, old, new):
        wallet = window.wallet
        if self.is_autofusing(wallet):
            try:
                self.enable_autofusing(wallet, new)
                self.print_error(wallet, "updated autofusion password")
            except InvalidPassword:
                self.disable_autofusing(wallet)
                self.print_error(wallet, "disabled autofusion due to incorrect password - BUG")

    def show_util_window(self, ):
        if self.utilwin is None:
            # keep a singleton around
            self.utilwin = UtilWindow(self)
            self.widgets.add(self.utilwin)
        self.utilwin.show()
        self.utilwin.raise_()

    def requires_settings(self):
        # called from main_window.py internal_plugins_dialog
        return True
    def settings_widget(self, window):
        # called from main_window.py internal_plugins_dialog
        btn = QPushButton(_('Settings'))
        btn.clicked.connect(self.show_settings_dialog)
        return btn

    def show_settings_dialog(self, ):
        if self.settingswin is None:
            # keep a singleton around
            self.settingswin = SettingsDialog(self, self.config)
            self.widgets.add(self.settingswin)
        self.settingswin.show()
        self.settingswin.raise_()


class PasswordDialog(QDialog):
    """ Slightly fancier password dialog -- can be used non-modal (asynchronous) and has internal password checking.
    To run non-modally, use .show with the callbacks; to run modally, use .run. """
    def __init__(self, parent, wallet, message, callback_ok = None, callback_cancel = None):
        super().__init__(parent=parent)
        self.setWindowTitle(_("Password"))
        self.wallet = wallet
        self.callback_ok = callback_ok
        self.callback_cancel = callback_cancel
        self.password = None

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        msglabel = QLabel(message)
        msglabel.setWordWrap(True)
        vbox.addWidget(msglabel)
        self.pwle = QLineEdit()
        self.pwle.setEchoMode(2)
        vbox.addWidget(self.pwle)
        self.badpass = QLabel("<i>" + _("Incorrect password entered. Please try again.") + "</i>")
        qs = QSizePolicy()
        qs.setRetainSizeWhenHidden(True)
        self.badpass.setSizePolicy(qs)
        vbox.addWidget(self.badpass)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancelbutton = QPushButton(_("Cancel"))
        cancelbutton.clicked.connect(self.reject)
        buttons.addWidget(cancelbutton)
        okbutton = QPushButton(_("OK"))
        okbutton.setDefault(True)
        okbutton.clicked.connect(self.pw_entered)
        buttons.addWidget(okbutton)
        vbox.addLayout(buttons)

        self.badpass.hide()

    def pw_entered(self, ):
        password = self.pwle.text()
        try:
            self.wallet.check_password(password)
            pw_ok = True
        except InvalidPassword:
            pw_ok = False
        if pw_ok:
            self.accept()
            self.password = password
            if self.callback_ok:
                self.callback_ok(password)
        else:
            self.badpass.show()
            self.pwle.clear()
            self.pwle.setFocus()

    def closeEvent(self, event):
        if not self.result() and self.callback_cancel:
            self.callback_cancel(self)
        self.setParent(None)
        self.deleteLater()

    def run(self):
        self.exec_()
        return self.password


class FusionButton(StatusBarButton):
    def __init__(self, plugin, wallet):
        super().__init__(QIcon(), 'Fusion', self.toggle_autofuse)

        self.plugin = plugin
        self.wallet = wallet

        self.icon_autofusing_on = icon_fusion_logo
        self.icon_autofusing_off = icon_fusion_logo_gray
        self.icon_fusing_problem = self.style().standardIcon(QStyle.SP_MessageBoxWarning)

#        title = QWidgetAction(self)
#        title.setDefaultWidget(QLabel("<i>" + _("CashFusion") + "</i>"))
        self.action_toggle = QAction(_("Auto-fuse in background"))
        self.action_toggle.setCheckable(True)
        self.action_toggle.triggered.connect(self.toggle_autofuse)
        action_wsettings = QAction(_("Wallet settings..."), self)
        action_wsettings.triggered.connect(self.show_wallet_settings)
        action_settings = QAction(_("CashFusion settings..."), self)
        action_settings.triggered.connect(self.plugin.show_settings_dialog)

        self.addActions([self.action_toggle, action_wsettings, action_settings])

        self.setContextMenuPolicy(Qt.ActionsContextMenu)

        self.update_state()

    def update_state(self):
        autofuse = self.plugin.is_autofusing(self.wallet)
        self.action_toggle.setChecked(autofuse)
        if autofuse:
            self.setIcon(self.icon_autofusing_on)
            self.setToolTip(_('CashFusion is fusing in background'))
        else:
            self.setIcon(self.icon_autofusing_off)
            self.setToolTip(_('CashFusion is paused'))

    def toggle_autofuse(self):
        autofuse = self.plugin.is_autofusing(self.wallet)
        if not autofuse:
            password = None
            if self.wallet.has_password():
                password = PasswordDialog(self, self.wallet, _("To perform auto-fusing in background, enter your password.")).run()
                if password is None:
                    return
            self.plugin.enable_autofusing(self.wallet, password)
        else:
            running = self.plugin.disable_autofusing(self.wallet)
            if running:
                res = QMessageBox.question(self, _("Disabling automatic Cash Fusions"),
                                           _("New automatic fusions will not be started, but you have %(num)d currently in progress. Would you like to signal them to stop?")%dict(num=len(running)),
                                           )
                if res == QMessageBox.Yes:
                    for f in running:
                        f.stop('Stop requested by user')
        self.update_state()

    def show_wallet_settings(self):
        win = WalletSettingsDialog(self, self.plugin, self.wallet)
        win.show()
        win.raise_()

class SettingsDialog(QDialog):
    torscanthread = None
    torscanthread_update = pyqtSignal(object)

    def __init__(self, plugin, config):
        super().__init__()
        self.plugin = plugin
        self.config = config
        self.torscanthread_ping = threading.Event()
        self.torscanthread_update.connect(self.torport_update)

        self.setWindowTitle(_("CashFusion settings"))
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        box = QGroupBox(_("Network")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)

        grid = QGridLayout() ; slayout.addLayout(grid)

        grid.addWidget(QLabel(_("Server")), 0, 0)
        hbox = QHBoxLayout(); grid.addLayout(hbox, 0, 1)
        self.combo_server_host = QComboBox()
        self.combo_server_host.setEditable(True)
        self.combo_server_host.setInsertPolicy(QComboBox.NoInsert)
        self.combo_server_host.setCompleter(None)
        self.combo_server_host.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.combo_server_host.activated.connect(self.combo_server_activated)
        self.combo_server_host.lineEdit().textEdited.connect(self.user_changed_server)
        self.combo_server_host.addItems([f'{s[0]} ({s[1]}{" - ssl" if s[2] else ""})' for s in server_list])
        hbox.addWidget(self.combo_server_host)
        hbox.addWidget(QLabel(_("P:")))
        self.le_server_port = QLineEdit()
        self.le_server_port.setMaximumWidth(50)
        self.le_server_port.textEdited.connect(self.user_changed_server)
        hbox.addWidget(self.le_server_port)
        self.cb_server_ssl = QCheckBox(_('SSL'))
        self.cb_server_ssl.clicked.connect(self.user_changed_server)
        hbox.addWidget(self.cb_server_ssl)

        grid.addWidget(QLabel(_("Tor")), 1, 0)
        hbox = QHBoxLayout(); grid.addLayout(hbox, 1, 1)
        self.le_tor_host = QLineEdit('localhost')
        self.le_tor_host.textEdited.connect(self.user_edit_torhost)
        hbox.addWidget(self.le_tor_host)
        hbox.addWidget(QLabel(_("P:")))
        self.le_tor_port = QLineEdit()
        self.le_tor_port.setMaximumWidth(50)
        self.le_tor_port.setValidator(QIntValidator(0, 65535))
        self.le_tor_port.textEdited.connect(self.user_edit_torport)
        hbox.addWidget(self.le_tor_port)
        self.l_tor_status = QLabel()
        hbox.addWidget(self.l_tor_status)
        self.b_tor_refresh = QPushButton()
        self.b_tor_refresh.clicked.connect(self.torscanthread_ping.set)
        self.b_tor_refresh.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        hbox.addWidget(self.b_tor_refresh)
        self.cb_tor_auto = QCheckBox(_('autodetect'))
        self.cb_tor_auto.clicked.connect(self.cb_tor_auto_clicked)
        hbox.addWidget(self.cb_tor_auto)

        btn = QPushButton(_("Utility..."))
        btn.clicked.connect(self.plugin.show_util_window)
        main_layout.addLayout(Buttons(btn, CloseButton(self)))

        self.pm_good_proxy = QIcon(":icons/status_connected_proxy.svg").pixmap(24)
        self.pm_bad_proxy = QIcon(":icons/status_disconnected.svg").pixmap(24)


        self.update_server()
        self.update_tor()

    def update_server(self):
        # called initially / when config changes
        host, port, ssl = self.plugin.get_server()
        try: # see if it's in default list, if so we can set it ...
            index = server_list.index((host,port,ssl))
        except ValueError: # not in list
            index = -1
        self.combo_server_host.setCurrentIndex(index)
        self.combo_server_host.setEditText(host)
        self.le_server_port.setText(str(port))
        self.cb_server_ssl.setChecked(ssl)

    def combo_server_activated(self, index):
        # only triggered when user selects a combo item
        self.plugin.set_server(*server_list[index])
        self.update_server()

    def user_changed_server(self, *args):
        # user edited the host / port / ssl
        host = self.combo_server_host.currentText()
        try:
            port = int(self.le_server_port.text())
        except ValueError:
            port = 0
        ssl = self.cb_server_ssl.isChecked()
        self.plugin.set_server(host, port, ssl)

    def update_tor(self,):
        # called on init an switch of auto
        autoport = self.plugin.has_auto_torport()
        host = self.plugin.get_torhost()
        port = self.plugin.get_torport()
        self.l_tor_status.clear()
        self.torport_update(port)
        self.cb_tor_auto.setChecked(autoport)
        self.le_tor_host.setEnabled(not autoport)
        self.le_tor_host.setText(str(host))
        self.le_tor_port.setEnabled(not autoport)
        if not autoport:
            self.le_tor_port.setText(str(port))

    def torport_update(self, goodport):
        # signalled from the tor checker thread
        autoport = self.plugin.has_auto_torport()
        port = self.plugin.get_torport()
        if autoport:
            sport = '?' if port is None else str(port)
            self.le_tor_port.setText(sport)
        if goodport is None:
            self.l_tor_status.setPixmap(self.pm_bad_proxy)
            if autoport:
                self.l_tor_status.setToolTip(_('Cannot find a Tor proxy on ports %(ports)s.')%dict(ports=TOR_PORTS))
            else:
                self.l_tor_status.setToolTip(_('Cannot find a Tor proxy on port %(port)d.')%dict(port=port))
        else:
            self.l_tor_status.setToolTip(_('Found a valid Tor proxy on this port.'))
            self.l_tor_status.setPixmap(self.pm_good_proxy)

    def user_edit_torhost(self, host):
        self.plugin.set_torhost(host)
        self.torscanthread_ping.set()

    def user_edit_torport(self, sport):
        try:
            port = int(sport)
        except ValueError:
            return
        self.plugin.set_torport(port)
        self.torscanthread_ping.set()

    def cb_tor_auto_clicked(self, state):
        self.plugin.set_torport('auto' if state else 'manual')
        port = self.plugin.get_torport()
        if port is not None:
            self.le_tor_port.setText(str(port))
        self.torscanthread_ping.set()
        self.update_tor()

    def showEvent(self, event):
        if self.torscanthread is None:
            self.torscanthread = threading.Thread(name='Fusion-scan_torport_settings', target=self.scan_torport_loop)
            self.torscanthread.daemon = True
            self.torscanthread_stopping = False
            self.torscanthread.start()

    def closeEvent(self, event):
        self.torscanthread_stopping = True
        self.torscanthread_ping.set()
        self.torscanthread = None

    def scan_torport_loop(self, ):
        while not self.torscanthread_stopping:
            goodport = self.plugin.scan_torport()
            self.torscanthread_update.emit(goodport)
            self.torscanthread_ping.wait(10)
            self.torscanthread_ping.clear()

class WalletSettingsDialog(QDialog):
    def __init__(self, parent, plugin, wallet):
        super().__init__(parent=parent)
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.plugin = plugin
        self.wallet = wallet

        self.setWindowTitle(_("CashFusion wallet settings"))
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        box = QGroupBox(_("Auto-fusion coin selection")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)

        grid = QGridLayout() ; slayout.addLayout(grid)

        self.radio_select_size = QRadioButton(_("Typical amount (sats)"))
        grid.addWidget(self.radio_select_size, 0, 0)
        self.radio_select_fraction = QRadioButton(_("Random fraction (0-1)"))
        grid.addWidget(self.radio_select_fraction, 1, 0)
        self.radio_select_count = QRadioButton(_("Number of coins"))
        grid.addWidget(self.radio_select_count, 2, 0)

        self.radio_select_size.clicked.connect(self.edited_size)
        self.radio_select_fraction.clicked.connect(self.edited_fraction)
        self.radio_select_count.clicked.connect(self.edited_count)

        self.le_selector_size = QLineEdit()
        grid.addWidget(self.le_selector_size, 0, 1)
        self.le_selector_fraction = QLineEdit()
        grid.addWidget(self.le_selector_fraction, 1, 1)
        self.le_selector_count = QLineEdit()
        grid.addWidget(self.le_selector_count, 2, 1)

        self.le_selector_size.editingFinished.connect(self.edited_size)
        self.le_selector_fraction.editingFinished.connect(self.edited_fraction)
        self.le_selector_count.editingFinished.connect(self.edited_count)

        box = QGroupBox(_("Self-fusing")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)

        slayout.addWidget(QLabel(_("Allow this wallet to participate multiply in the same fusion round?")))
        self.combo_self_fuse = QComboBox()
        self.combo_self_fuse.addItem(_('No'), 1)
        self.combo_self_fuse.addItem(_('Yes - as up to two players'), 2)
        slayout.addWidget(self.combo_self_fuse)

        self.combo_self_fuse.activated.connect(self.chose_self_fuse)

        self.update()

    def update(self):
        self.le_selector_size.setEnabled(False)
        self.le_selector_fraction.setEnabled(False)
        self.le_selector_count.setEnabled(False)
        coinsum = sum(c['value'] for c in select_coins(self.wallet))
        select_type, select_amount = self.wallet.storage.get('cashfusion_selector', DEFAULT_SELECTOR)
        if select_type == 'size':
            self.le_selector_size.setEnabled(True)
            self.radio_select_size.setChecked(True)
            sel_size = select_amount
            if coinsum > 0:
                sel_fraction = min(COIN_FRACTION_FUDGE_FACTOR * select_amount / coinsum, 1)
            else:
                sel_fraction = 1
        elif select_type == 'count':
            self.le_selector_count.setEnabled(True)
            self.radio_select_count.setChecked(True)
            sel_size = max(coinsum / select_amount, 10000)
            sel_fraction = COIN_FRACTION_FUDGE_FACTOR / select_amount
        elif select_type == 'fraction':
            self.le_selector_fraction.setEnabled(True)
            self.radio_select_fraction.setChecked(True)
            sel_size = max(coinsum * select_amount / COIN_FRACTION_FUDGE_FACTOR, 10000)
            sel_fraction = select_amount
        else:
            self.wallet.storage.put('cashfusion_selector', None)
            return self.update()
        sel_count = COIN_FRACTION_FUDGE_FACTOR / sel_fraction
        self.le_selector_size.setText(str(round(sel_size)))
        self.le_selector_fraction.setText('%.03f' % (sel_fraction))
        self.le_selector_count.setText(str(round(sel_count)))
        self.combo_self_fuse.setCurrentIndex(self.wallet.storage.get('cashfusion_self_fuse_players', DEFAULT_SELF_FUSE) - 1)

    def edited_size(self,):
        try:
            size = int(self.le_selector_size.text())
            if size < 10000:
                size = 10000
        except Exception as e:
            pass
        else:
            self.wallet.storage.put('cashfusion_selector', ('size', size))
        self.update()

    def edited_fraction(self,):
        try:
            fraction = float(self.le_selector_fraction.text())
            fraction = max(0., min(fraction, 1.))
        except Exception as e:
            pass
        else:
            self.wallet.storage.put('cashfusion_selector', ('fraction', round(fraction, 3)))
        self.update()

    def edited_count(self,):
        try:
            count = int(self.le_selector_count.text())
            if count < COIN_FRACTION_FUDGE_FACTOR:
                count = COIN_FRACTION_FUDGE_FACTOR
        except Exception as e:
            pass
        else:
            self.wallet.storage.put('cashfusion_selector', ('count', count))
        self.update()

    def chose_self_fuse(self,):
        sel = self.combo_self_fuse.currentData()
        oldsel = self.wallet.storage.get('cashfusion_self_fuse_players', DEFAULT_SELF_FUSE)
        self.wallet.storage.put('cashfusion_self_fuse_players', sel)
        if oldsel != sel:
            for f in self.wallet._fusions:
                # we have to stop waiting fusions since the tags won't overlap.
                # otherwise, the user will end up self fusing way too much.
                f.stop('User changed self-fuse limit', not_if_running = True)
        self.update()

class UtilWindow(QDialog):
    def __init__(self, plugin):
        super().__init__(parent=plugin.settingswin)
        self.plugin = plugin

        self.setWindowTitle("CashFusion control")
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        clientbox = QGroupBox("Fusions")
        main_layout.addWidget(clientbox)

        self.serverbox = QGroupBox("Test server")
        main_layout.addWidget(self.serverbox)

        clayout = QVBoxLayout()
        clientbox.setLayout(clayout)

        self.t_active_fusions = QTreeWidget()
        self.t_active_fusions.setHeaderLabels(['wallet','status','status_ext'])
        self.t_active_fusions.setContextMenuPolicy(Qt.CustomContextMenu)
        self.t_active_fusions.customContextMenuRequested.connect(self.create_menu_active_fusions)
        self.t_active_fusions.setSelectionMode(QAbstractItemView.ExtendedSelection)
        clayout.addWidget(self.t_active_fusions)


        slayout = QVBoxLayout()
        self.serverbox.setLayout(slayout)

        self.l_server_status = QLabel()
        slayout.addWidget(self.l_server_status)

        self.t_server_waiting = QTableWidget()
        self.t_server_waiting.setColumnCount(3)
        self.t_server_waiting.setRowCount(len(Params.tiers))
        self.t_server_waiting.setHorizontalHeaderLabels(['Tier (sats)','Num players', ''])
        for i, t in enumerate(Params.tiers):
            button = QPushButton("Start")
            button.clicked.connect(partial(self.clicked_start_fuse, t))
            self.t_server_waiting.setCellWidget(i, 2, button)
        slayout.addWidget(self.t_server_waiting)


        self.timer_status_update = QTimer(self)
        self.timer_status_update.setSingleShot(False)
        self.timer_status_update.timeout.connect(self.update_status)
        self.timer_status_update.start(2000)

        self.update_status()

        self.show()

    def update_status(self):
        self.update_fusions()
        if self.plugin.testserver:
            self.l_server_status.setText(f'Test server status: ACTIVE {self.plugin.testserver.host}:{self.plugin.testserver.port}')
            table = self.t_server_waiting
            table.setRowCount(len(self.plugin.testserver.waiting_pools))
            for i,(t,pool) in enumerate(self.plugin.testserver.waiting_pools.items()):
                table.setItem(i,0,QTableWidgetItem(str(t)))
                table.setItem(i,1,QTableWidgetItem(str(len(pool.pool))))
            self.serverbox.show()
        else:
            self.serverbox.hide()

    def update_fusions(self):
        tree = self.t_active_fusions
        reselect_fusions = set(i.data(0, Qt.UserRole)() for i in tree.selectedItems())
        reselect_fusions.discard(None)
        reselect_items = []
        tree.clear()
        fusions_and_times = sorted(self.plugin.fusions.items(), key=lambda x:x[1], reverse=True)
        for fusion,t in fusions_and_times:
            wname = fusion.target_wallet.diagnostic_name()
            status, status_ext = fusion.status
            item = QTreeWidgetItem( [ wname, status, status_ext] )
            item.setData(0, Qt.UserRole, weakref.ref(fusion))
            if fusion in reselect_fusions:
                reselect_items.append(item)
            tree.addTopLevelItem(item)
        for item in reselect_items:
            item.setSelected(True)

    def create_menu_active_fusions(self, position):
        selected = self.t_active_fusions.selectedItems()
        if not selected:
            return

        fusions = set(i.data(0, Qt.UserRole)() for i in selected)
        fusions.discard(None)
        statuses = set(f.status[0] for f in fusions)
        has_live = 'running' in statuses or 'waiting' in statuses

        menu = QMenu()
        def cancel():
            for fusion in fusions:
                fusion.stop('Stop requested by user')
        if has_live:
            if 'running' in statuses:
                msg = _('Cancel (at end of round)')
            else:
                msg = _('Cancel')
            menu.addAction(msg, cancel)
        if not menu.isEmpty():
            menu.exec_(self.t_active_fusions.viewport().mapToGlobal(position))

    def clicked_start_fuse(self, tier, event):
        if self.plugin.testserver is None:
            return
        self.plugin.testserver.start_fuse(tier)
