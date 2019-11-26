"""
Magic parameters for the protocol that need to be followed uniformly by
participants either for functionality or for privacy reasons. Unlike
flexible server params these do need to be fixed and implicitly shared.

Any time the values are changed, the version should be bumped to avoid
having loss of function, or theoretical privacy loss.
"""

from . import pedersen

# this class doesn't get instantiated, it's just a bag of values.
class Protocol:
    VERSION = b'alpha7'
    PEDERSEN = pedersen.PedersenSetup(b'\x02CashFusion gives us fungibility.')

    # The server only enforces dust limits, but clients should not make outputs
    # smaller than this.
    MIN_OUTPUT = 10000

    # Covert connection timescales
    # don't let connection attempts take longer than this, since they need to be finished early enough that a spare can be tried.
    COVERT_CONNECT_TIMEOUT = 15.0
    # likewise for submitted data (which is quite small), we don't want it going too late.
    COVERT_SUBMIT_TIMEOUT = 3.0
    # What timespan to make covert submissions over.
    COVERT_SUBMIT_WINDOW = 5.0


    ### Critical timeline ###
    # (For early phases in a round)
    # For client privacy, it is critical that covert submissions happen within
    # very specific windows so that they know the server is not able to pull
    # off a strong timing partition.

    # T_* are client times measured from receipt of startround message.
    # TS_* are server times measured from send of startround message.

    # The timing interval over which clients attempt Tor connections. Note that
    # they can be very slow to connect (see the timeout above)
    T_FIRST_CONNECT = +0.0
    T_LAST_CONNECT = +5.0

    # The server expects all commitments by this time, so it can start uploading them.
    TS_EXPECTING_COMMITMENTS = +3.0

    # when to start submitting covert components; the BlindSigResponses must have been received by this time.
    T_START_COMPS = +15.0
    # submission nominally stops at +20.0, but could be lagged if timeout and spares need to be used.

    # the server will reject all components received after this time.
    TS_EXPECTING_COVERT_COMPONENTS = +25.0

    # At this point the server needs to generate the tx template and calculate
    # all sighashes in order to prepare for receiving signatures, and then send
    # ShareCovertComponents (a large message, may need time for clients to download).

    # when to start submitting signatures; the ShareCovertComponents must be received by this time.
    T_START_SIGS = +30.0
    # submission nominally stops at +35.0, but could be lagged if timeout and spares need to be used.

    # the server will reject all signatures received after this time.
    TS_EXPECTING_COVERT_SIGNATURES = +40.0

    # When to start closing connections. It is likely the server has already
    # closed, but client needs to do this just in case.
    T_START_CLOSE = +45.0

    # At this point the server assembles the tx and tries to broadcast it.
    # It then informs clients of success or fail.

    # After submissing sigs, clients expect to hear back a result by this time.
    T_EXPECTING_CONCLUSION = 45.0

    ### (End critical timeline) ###


    # For non-critical messages like during blame phase, just regular relative timeouts are needed.
    # Note that when clients send a result and expect a 'gathered' response from server, they wait
    # twice this long to allow for other slow clients.
    STANDARD_TIMEOUT = 3.
    # How much extra time to allow for a peer to check blames (this may involve querying blockchain).
    BLAME_VERIFY_TIME = 5.


del pedersen
