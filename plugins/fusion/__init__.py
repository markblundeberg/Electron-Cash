from electroncash.i18n import _

fullname = _('CashFusion')
description = ''.join([
    _('Protect your privacy and anonymize your coins (UTXOs) by shuffling them with other users of CashFusion.'), "\n\n",
    _('A commitment and anonymous announcement scheme is used so that none of the participants know the inputs nor outputs of the other participants.'), " ",
    _('In addition, a blame protocol is used to mitigate time-wasting denial-of-service type attacks.')
])
available_for = ['qt', 'cmdline']
