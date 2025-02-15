#!/usr/bin/env python
# coding=utf-8
from __future__ import print_function, unicode_literals, division, absolute_import
import sys
import time
import binascii
import struct
import collections
import logging
import socket
import functools
import threading
import traceback
import warnings

try:
    import selectors
    from selectors import EVENT_READ, EVENT_WRITE

    EVENT_READ_WRITE = EVENT_READ | EVENT_WRITE
except ImportError:
    import select

    warnings.warn('selectors module not available, fallback to select')
    selectors = None

try:
    import ssl
except ImportError:
    ssl = None
    warnings.warn('ssl module not available, ssl feature is disabled')

try:
    # for pycharm type hinting
    from typing import Union, Callable
except:
    pass
    
import setproctitle

# socket recv buffer, 16384 bytes
RECV_BUFFER_SIZE = 2 ** 14

# default secretkey, use -k/--secretkey to change
SECRET_KEY = None  # "shootback"

# how long a SPARE slaver would keep
# once slaver received an heart-beat package from master,
#   the TTL would be reset. And heart-beat delay is less than TTL,
#   so, theoretically, spare slaver never timeout,
#   except network failure
# notice: working slaver would NEVER timeout
SPARE_SLAVER_TTL = 300

# internal program version, appears in CtrlPkg
INTERNAL_VERSION = 0x0012

# # how many packet are buffed, before delaying recv
# SOCKET_BRIDGE_SEND_BUFF_SIZE = 5

# version for human readable
__version__ = (2, 6, 0, INTERNAL_VERSION)

# just a logger
log = logging.getLogger(__name__)


def version_info():
    """get program version for human. eg: "2.1.0-r2" """
    return "{}.{}.{}-r{}".format(*__version__)


def configure_logging(level):
    logging.basicConfig(
        level=level,
        format='[%(levelname)s %(asctime)s] %(message)s',
    )


def fmt_addr(socket):
    """(host, int(port)) --> "host:port" """
    return "{}:{}".format(*socket)


def split_host(x):
    """ "host:port" --> (host, int(port))"""
    try:
        host, port = x.split(":")
        port = int(port)
    except:
        raise ValueError(
            "wrong syntax, format host:port is "
            "required, not {}".format(x))
    else:
        return host, port


def try_close(closable):
    """try close something

    same as
        try:
            connection.close()
        except:
            pass
    """
    try:
        closable.close()
    except:
        pass


def select_recv(conn, buff_size, timeout=None):
    """add timeout for socket.recv()
    :type conn: socket.socket
    :type buff_size: int
    :type timeout: float
    :rtype: Union[bytes, None]
    """
    if selectors:
        sel = selectors.DefaultSelector()
        sel.register(conn, EVENT_READ)
        events = sel.select(timeout)
        sel.close()
        if not events:
            # timeout
            raise RuntimeError("recv timeout")
    else:
        rlist, _, _ = select.select([conn], [], [], timeout)

    buff = conn.recv(buff_size)
    if not buff:
        raise RuntimeError("received zero bytes, socket was closed")

    return buff


def set_secretkey(key):
    global SECRET_KEY
    SECRET_KEY = key
    CtrlPkg.recalc_crc32()


class SocketBridge(object):
    """
    transfer data between sockets
    """

    def __init__(self):
        self.conn_rd = set()  # record readable-sockets
        self.conn_wr = set()  # record writeable-sockets
        self.map = {}  # record sockets pairs
        self.callbacks = {}  # record callbacks
        self.send_buff = {}  # buff one packet for those sending too-fast socket

        if selectors:
            self.sel = selectors.DefaultSelector()
        else:
            self.sel = None

    def add_conn_pair(self, conn1, conn2, callback=None):
        """
        transfer anything between two sockets

        :type conn1: socket.socket
        :type conn2: socket.socket
        :param callback: callback in connection finish
        :type callback: Callable
        """
        # change to non-blocking
        #   we use select or epoll to notice when data is ready
        conn1.setblocking(False)
        conn2.setblocking(False)

        # mark as readable+writable
        self.conn_rd.add(conn1)
        self.conn_wr.add(conn1)
        self.conn_rd.add(conn2)
        self.conn_wr.add(conn2)

        # record sockets pairs
        self.map[conn1] = conn2
        self.map[conn2] = conn1

        # record callback
        if callback is not None:
            self.callbacks[conn1] = callback

        if self.sel:
            self.sel.register(conn1, EVENT_READ_WRITE)
            self.sel.register(conn2, EVENT_READ_WRITE)

    def start_as_daemon(self):
        t = threading.Thread(target=self.start)
        t.daemon = True
        t.start()
        log.info("SocketBridge daemon started")
        return t

    def start(self):
        while True:
            try:
                self._start()
            except:
                log.error("FATAL ERROR! SocketBridge failed {}".format(
                    traceback.format_exc()
                ))

    def _start(self):

        while True:
            if not self.conn_rd and not self.conn_wr:
                # sleep if there is no connections
                time.sleep(0.06)
                continue

            # blocks until there is socket(s) ready for .recv
            # notice: sockets which were closed by remote,
            #   are also regarded as read-ready by select()
            if self.sel:
                events = self.sel.select(0.5)
                socks_rd = tuple(key.fileobj for key, mask in events if mask & EVENT_READ)
                socks_wr = tuple(key.fileobj for key, mask in events if mask & EVENT_WRITE)
            else:
                r, w, _ = select.select(self.conn_rd, self.conn_wr, [], 0.5)
                socks_rd = tuple(r)
                socks_wr = tuple(w)
                # log.debug('socks_rd: %s, socks_wr:%s', len(socks_rd), len(socks_wr))

            if not socks_rd and not self.send_buff:  # reduce CPU in low traffic
                time.sleep(0.01)
            # log.debug('got rd:%s wr:%s', socks_rd, socks_wr)

            # ----------------- RECEIVING ----------------
            for s in socks_rd:  # type: socket.socket
                # if this socket has non-sent data, stop recving more, to prevent buff blowing up.
                if self.map[s] in self.send_buff:
                    # log.debug('delay recv because another too slow %s', self.map.get(s))
                    continue

                try:
                    received = s.recv(RECV_BUFFER_SIZE)
                    # log.debug('recved %s from %s', len(received), s)
                except Exception as e:
                    # ssl may raise SSLWantReadError or SSLWantWriteError
                    #   just continue and wait it complete
                    if ssl and isinstance(e, (ssl.SSLWantReadError, ssl.SSLWantWriteError)):
                        # log.warning('got %s, wait to read then', repr(e))
                        continue

                    # unable to read, in most cases, it's due to socket close
                    log.warning('error reading socket %s, %s closing', repr(e), s)
                    self._rd_shutdown(s)
                    continue

                if not received:
                    self._rd_shutdown(s)
                    continue
                else:
                    self.send_buff[self.map[s]] = received

            # ----------------- SENDING ----------------
            for s in socks_wr:
                if s not in self.send_buff:
                    if self.map.get(s) not in self.conn_rd:
                        self._wr_shutdown(s)
                    continue
                data = self.send_buff.pop(s)
                try:
                    s.send(data)
                    # log.debug('sent %s to %s', len(data), s)
                except Exception as e:
                    if ssl and isinstance(e, (ssl.SSLWantReadError, ssl.SSLWantWriteError)):
                        # log.warning('got %s, wait to write then', repr(e))
                        self.send_buff[s] = data  # write back for next write
                        continue
                    # unable to send, close connection
                    log.warning('error sending socket %s, %s closing', repr(e), s)
                    self._wr_shutdown(s)
                    continue

    def _sel_disable_event(self, conn, ev):
        try:
            _key = self.sel.get_key(conn)  # type:selectors.SelectorKey
        except KeyError:
            pass
        else:
            if _key.events == EVENT_READ_WRITE:
                self.sel.modify(conn, EVENT_READ_WRITE ^ ev)
            else:
                self.sel.unregister(conn)

    def _rd_shutdown(self, conn, once=False):
        """action when connection should be read-shutdown
        :type conn: socket.socket
        """
        if conn in self.conn_rd:
            self.conn_rd.remove(conn)
            if self.sel:
                self._sel_disable_event(conn, EVENT_READ)

        # if conn in self.send_buff:
        #     del self.send_buff[conn]

        try:
            conn.shutdown(socket.SHUT_RD)
        except:
            pass

        if not once and conn in self.map:  # use the `once` param to avoid infinite loop
            # if a socket is rd_shutdowned, then it's
            #   pair should be wr_shutdown.
            self._wr_shutdown(self.map[conn], True)

        if self.map.get(conn) not in self.conn_rd:
            # if both two connection pair was rd-shutdowned,
            #   this pair sockets are regarded to be completed
            #   so we gonna close them
            self._terminate(conn)

    def _wr_shutdown(self, conn, once=False):
        """action when connection should be write-shutdown
        :type conn: socket.socket
        """
        try:
            conn.shutdown(socket.SHUT_WR)
        except:
            pass

        if conn in self.conn_wr:
            self.conn_wr.remove(conn)
            if self.sel:
                self._sel_disable_event(conn, EVENT_WRITE)

        if not once and conn in self.map:  # use the `once` param to avoid infinite loop
            #   pair should be rd_shutdown.
            # if a socket is wr_shutdowned, then it's
            self._rd_shutdown(self.map[conn], True)

    def _terminate(self, conn, once=False):
        """terminate a sockets pair (two socket)
        :type conn: socket.socket
        :param conn: any one of the sockets pair
        """
        try_close(conn)  # close the first socket

        # ------ close and clean the mapped socket, if exist ------
        _another_conn = self.map.pop(conn, None)

        self.send_buff.pop(conn, None)
        if self.sel:
            try:
                self.sel.unregister(conn)
            except:
                pass

        # ------ callback --------
        # because we are not sure which socket are assigned to callback,
        #   so we should try both
        if conn in self.callbacks:
            try:
                self.callbacks[conn]()
            except Exception as e:
                log.error("traceback error: {}".format(e))
                log.debug(traceback.format_exc())
            del self.callbacks[conn]

        # terminate another
        if not once and _another_conn in self.map:
            self._terminate(_another_conn)


class CtrlPkg(object):
    """
    Control Packages of shootback, not completed yet
    current we have: handshake and heartbeat

    NOTICE: If you are non-Chinese reader,
        please contact me for the following Chinese comment's translation
        http://github.com/aploium

    控制包结构 总长64bytes      CtrlPkg.FORMAT_PKG
    使用 big-endian

    体积   名称        数据类型           描述
    1    pkg_ver    unsigned char       包版本  *1
    1    pkg_type    signed char        包类型 *2
    2    prgm_ver    unsigned short    程序版本 *3
    20    N/A          N/A              预留
    40    data        bytes           数据区 *4

    *1: 包版本. 包整体结构的定义版本, 目前只有 0x01

    *2: 包类型. 除心跳外, 所有负数包代表由Slaver发出, 正数包由Master发出
        -1: Slaver-->Master 的握手响应包       PTYPE_HS_S2M
         0: 心跳包                            PTYPE_HEART_BEAT
        +1: Master-->Slaver 的握手包          PTYPE_HS_M2S

    *3: 默认即为 INTERNAL_VERSION

    *4: 数据区中的内容由各个类型的包自身定义

    -------------- 数据区定义 ------------------
    包类型: -1 (Slaver-->Master 的握手响应包)
        体积   名称           数据类型         描述
         4    crc32_s2m   unsigned int     简单鉴权用 CRC32(Reversed(SECRET_KEY))
         1    ssl_flag   unsigned char     是否支持SSL
       其余为空
       *注意: -1握手包是把 SECRET_KEY 字符串翻转后取CRC32, +1握手包不预先反转

    包类型: 0 (心跳)
       数据区为空

    包理性: +1 (Master-->Slaver 的握手包)
        体积   名称           数据类型         描述
         4    crc32_m2s   unsigned int     简单鉴权用 CRC32(SECRET_KEY)
         1    ssl_flag   unsigned char     是否支持SSL
       其余为空

    """
    PACKAGE_SIZE = 2 ** 6  # 64 bytes
    CTRL_PKG_TIMEOUT = 5  # CtrlPkg recv timeout, in second

    # CRC32 for SECRET_KEY and Reversed(SECRET_KEY)
    #   these values are set by `set_secretkey`
    SECRET_KEY_CRC32 = None  # binascii.crc32(SECRET_KEY.encode('utf-8')) & 0xffffffff
    SECRET_KEY_REVERSED_CRC32 = None  # binascii.crc32(SECRET_KEY[::-1].encode('utf-8')) & 0xffffffff

    # Package Type
    PTYPE_HS_S2M = -1  # handshake pkg, slaver to master
    PTYPE_HEART_BEAT = 0  # heart beat pkg
    PTYPE_HS_M2S = +1  # handshake pkg, Master to Slaver

    TYPE_NAME_MAP = {
        PTYPE_HS_S2M: "PTYPE_HS_S2M",
        PTYPE_HEART_BEAT: "PTYPE_HEART_BEAT",
        PTYPE_HS_M2S: "PTYPE_HS_M2S",
    }

    # formats
    # see https://docs.python.org/3/library/struct.html#format-characters
    #   for format syntax
    FORMAT_PKG = b"!b b H 20x 40s"
    FORMATS_DATA = {
        PTYPE_HS_S2M: b"!I B 35x",
        PTYPE_HEART_BEAT: b"!40x",
        PTYPE_HS_M2S: b"!I B 35x",
    }

    SSL_FLAG_NONE = 0
    SSL_FLAG_AVAIL = 1

    def __init__(self, pkg_ver=0x01, pkg_type=0,
                 prgm_ver=INTERNAL_VERSION, data=(),
                 raw=None,
                 ):
        """do not call this directly, use `CtrlPkg.pbuild_*` instead"""
        self.pkg_ver = pkg_ver
        self.pkg_type = pkg_type
        self.prgm_ver = prgm_ver
        self.data = data
        if raw:
            self.raw = raw
        else:
            self._build_bytes()

    @property
    def type_name(self):
        """返回人类可读的包类型"""
        return self.TYPE_NAME_MAP.get(self.pkg_type, "TypeUnknown")

    def __str__(self):
        return """pkg_ver: {} pkg_type:{} prgm_ver:{} data:{}""".format(
            self.pkg_ver,
            self.type_name,
            self.prgm_ver,
            self.data,
        )

    def __repr__(self):
        return self.__str__()

    def _build_bytes(self):
        self.raw = struct.pack(
            self.FORMAT_PKG,
            self.pkg_ver,
            self.pkg_type,
            self.prgm_ver,
            self.data_encode(self.pkg_type, self.data),
        )

    @classmethod
    def recalc_crc32(cls):
        cls.SECRET_KEY_CRC32 = binascii.crc32(SECRET_KEY.encode('utf-8')) & 0xffffffff
        cls.SECRET_KEY_REVERSED_CRC32 = binascii.crc32(SECRET_KEY[::-1].encode('utf-8')) & 0xffffffff

    @classmethod
    def data_decode(cls, ptype, data_raw):
        return struct.unpack(cls.FORMATS_DATA[ptype], data_raw)

    @classmethod
    def data_encode(cls, ptype, data):
        return struct.pack(cls.FORMATS_DATA[ptype], *data)

    def verify(self, pkg_type=None):
        try:
            if pkg_type is not None and self.pkg_type != pkg_type:
                return False
            elif self.pkg_type == self.PTYPE_HS_S2M:
                # Slaver-->Master 的握手响应包
                return self.data[0] == self.SECRET_KEY_REVERSED_CRC32

            elif self.pkg_type == self.PTYPE_HEART_BEAT:
                # 心跳
                return True

            elif self.pkg_type == self.PTYPE_HS_M2S:
                # Master-->Slaver 的握手包
                return self.data[0] == self.SECRET_KEY_CRC32

            else:
                return True
        except:
            return False

    @classmethod
    def decode_only(cls, raw):
        """
        decode raw bytes to CtrlPkg instance, no verify
        use .decode_verify() if you also want verify

        :param raw: raw bytes content of package
        :type raw: bytes
        :rtype: CtrlPkg
        """
        if not raw or len(raw) != cls.PACKAGE_SIZE:
            raise ValueError("content size should be {}, but {}".format(
                cls.PACKAGE_SIZE, len(raw)
            ))
        pkg_ver, pkg_type, prgm_ver, data_raw = struct.unpack(cls.FORMAT_PKG, raw)
        data = cls.data_decode(pkg_type, data_raw)

        return cls(
            pkg_ver=pkg_ver, pkg_type=pkg_type,
            prgm_ver=prgm_ver,
            data=data,
            raw=raw,
        )

    @classmethod
    def decode_verify(cls, raw, pkg_type=None):
        """decode and verify a package
        :param raw: raw bytes content of package
        :type raw: bytes
        :param pkg_type: assert this package's type,
            if type not match, would be marked as wrong
        :type pkg_type: int

        :rtype: CtrlPkg, bool
        :return: tuple(CtrlPkg, is_it_a_valid_package)
        """
        try:
            pkg = cls.decode_only(raw)
        except:
            log.error('unable to decode package. raw: %s', raw, exc_info=True)
            return None, False
        else:
            return pkg, pkg.verify(pkg_type=pkg_type)

    @classmethod
    def pbuild_hs_m2s(cls, ssl_avail=False):
        """pkg build: Handshake Master to Slaver
        """
        ssl_flag = cls.SSL_FLAG_AVAIL if ssl_avail else cls.SSL_FLAG_NONE
        return cls(
            pkg_type=cls.PTYPE_HS_M2S,
            data=(cls.SECRET_KEY_CRC32, ssl_flag),
        )

    @classmethod
    def pbuild_hs_s2m(cls, ssl_avail=False):
        """pkg build: Handshake Slaver to Master"""
        ssl_flag = cls.SSL_FLAG_AVAIL if ssl_avail else cls.SSL_FLAG_NONE
        return cls(
            pkg_type=cls.PTYPE_HS_S2M,
            data=(cls.SECRET_KEY_REVERSED_CRC32, ssl_flag),
        )

    @classmethod
    def pbuild_heart_beat(cls):
        """pkg build: Heart Beat Package"""
        return cls(
            pkg_type=cls.PTYPE_HEART_BEAT,
        )

    @classmethod
    def recv(cls, sock, timeout=CTRL_PKG_TIMEOUT, expect_ptype=None):
        """just a shortcut function
        :param sock: which socket to recv CtrlPkg from
        :type sock: socket.socket
        :rtype: CtrlPkg,bool
        """
        buff = select_recv(sock, cls.PACKAGE_SIZE, timeout)
        pkg, verify = CtrlPkg.decode_verify(buff, pkg_type=expect_ptype)  # type: CtrlPkg,bool
        return pkg, verify
#!/usr/bin/env python3
# coding=utf-8
# from __future__ import print_function, unicode_literals, division, absolute_import

# from common_func import *

__author__ = "Aploium <i@z.codes>"
__website__ = "https://github.com/aploium/shootback"


class Slaver(object):
    """
    slaver socket阶段
        连接master->等待->心跳(重复)--->握手-->正式传输数据->退出
    """

    def __init__(self, communicate_addr, target_addr, max_spare_count=5, ssl=False):
        self.communicate_addr = communicate_addr
        self.target_addr = target_addr
        self.max_spare_count = max_spare_count

        self.spare_slaver_pool = {}
        self.working_pool = {}
        self.socket_bridge = SocketBridge()

        if ssl:
            self.ssl_context = self._make_ssl_context()
            self.ssl_avail = self.ssl_context is not None
        else:
            self.ssl_avail = False
            self.ssl_context = None

    def _make_ssl_context(self):
        if ssl is None:
            log.warning('ssl module is NOT valid in this machine! Fallback to plain')
            return None

        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.check_hostname = False
        ctx.load_default_certs(ssl.Purpose.CLIENT_AUTH)
        ctx.verify_mode = ssl.CERT_NONE

        return ctx

    def _connect_master(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.communicate_addr)

        self.spare_slaver_pool[sock.getsockname()] = {
            "conn_slaver": sock,
        }

        return sock

    def _connect_target(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.target_addr)

        log.debug("connected to target[{}] at: {}".format(
            sock.getpeername(),
            sock.getsockname(),
        ))

        return sock

    def _response_heartbeat(self, conn_slaver, hb_from_master):
        # assert isinstance(hb_from_master, CtrlPkg)
        # assert isinstance(conn_slaver, socket.SocketType)
        if hb_from_master.prgm_ver < 0x000B:
            # shootback before 2.2.5-r10 use two-way heartbeat
            #   so just send a heart_beat pkg back
            conn_slaver.send(CtrlPkg.pbuild_heart_beat().raw)
            return True
        else:
            # newer version use TCP-like 3-way heartbeat
            #   the older 2-way heartbeat can't only ensure the
            #   master --> slaver pathway is OK, but the reverse
            #   communicate may down. So we need a TCP-like 3-way
            #   heartbeat
            conn_slaver.send(CtrlPkg.pbuild_heart_beat().raw)
            pkg, verify = CtrlPkg.recv(
                conn_slaver,
                expect_ptype=CtrlPkg.PTYPE_HEART_BEAT)  # type: CtrlPkg,bool
            if verify:
                log.debug("heartbeat success {}".format(
                    fmt_addr(conn_slaver.getsockname())))
                return True
            else:
                log.warning(
                    "received a wrong pkg[{}] during heartbeat, {}".format(
                        pkg, conn_slaver.getsockname()
                    ))
                return False

    def _stage_ctrlpkg(self, conn_slaver):
        """
        handling CtrlPkg until handshake

        well, there is only one CtrlPkg: heartbeat, yet

        it ensures:
            1. network is ok, master is alive
            2. master is shootback_master, not bad guy
            3. verify the SECRET_KEY
            4. tell slaver it's time to connect target

        handshake procedure:
            1. master hello --> slaver
            2. slaver verify master's hello
            3. slaver hello --> master
            4. (immediately after 3) slaver connect to target
            4. master verify slaver
            5. enter real data transfer
        """
        while True:  # 可能会有一段时间的心跳包

            # recv master --> slaver
            # timeout is set to `SPARE_SLAVER_TTL`
            # which means if not receive pkg from master in SPARE_SLAVER_TTL seconds,
            #   this connection would expire and re-connect
            pkg, correct = CtrlPkg.recv(conn_slaver, SPARE_SLAVER_TTL)  # type: CtrlPkg,bool

            if not correct:
                return None

            log.debug("CtrlPkg from {}: {}".format(conn_slaver.getpeername(), pkg))

            if pkg.pkg_type == CtrlPkg.PTYPE_HEART_BEAT:
                # if the pkg is heartbeat pkg, enter handshake procedure
                if not self._response_heartbeat(conn_slaver, pkg):
                    return None

            elif pkg.pkg_type == CtrlPkg.PTYPE_HS_M2S:
                # 拿到了开始传输的握手包, 进入工作阶段

                break

        # send slaver hello --> master
        actual_conn = self._response_handshake(conn_slaver, pkg)

        return actual_conn

    def _response_handshake(self, conn_slaver, handshake_pkg):
        """
        response master's handshake
        check if ssl is avail, if avail, establish ssl

        Args:
            conn_slaver (socket.socket):
            handshake_pkg (CtrlPkg):

        Returns:
            socket.socket|ssl.SSLSocket
        """
        conn_slaver.send(CtrlPkg.pbuild_hs_s2m(ssl_avail=self.ssl_avail).raw)

        if not self.ssl_avail or handshake_pkg.data[1] == CtrlPkg.SSL_FLAG_NONE:
            if self.ssl_avail:
                log.warning('master %s does not enabled SSL, fallback to plain', conn_slaver.getpeername())
            return conn_slaver
        else:
            ssl_conn_slaver = self.ssl_context.wrap_socket(conn_slaver, server_side=False)  # type: ssl.SSLSocket
            log.debug('ssl established slaver: %s', ssl_conn_slaver.getpeername())
            return ssl_conn_slaver

    def _transfer_complete(self, addr_slaver):
        """a callback for SocketBridge, do some cleanup jobs"""
        pair = self.working_pool.pop(addr_slaver)
        try_close(pair['conn_slaver'])
        try_close(pair['conn_target'])
        log.info("slaver complete: {}".format(addr_slaver))

    def _slaver_working(self, conn_slaver):
        addr_slaver = conn_slaver.getsockname()
        addr_master = conn_slaver.getpeername()

        # --------- handling CtrlPkg until handshake -------------
        try:
            actual_conn = self._stage_ctrlpkg(conn_slaver)
        except Exception as e:
            log.warning("slaver{} waiting handshake failed {}".format(
                fmt_addr(addr_slaver), e))
            log.debug(traceback.print_exc())
            actual_conn = None
        else:
            if actual_conn is None:
                log.warning("bad handshake or timeout between: {} and {}".format(
                    fmt_addr(addr_master), fmt_addr(addr_slaver)))

        if actual_conn is None:
            # handshake failed or timeout
            del self.spare_slaver_pool[addr_slaver]
            try_close(conn_slaver)

            log.warning("a slaver[{}] abort due to handshake error or timeout".format(
                fmt_addr(addr_slaver)))
            return
        else:
            log.info("Success master handshake from: {} to {}".format(
                fmt_addr(addr_master), fmt_addr(addr_slaver)))

        # ----------- slaver activated! ------------
        # move self from spare_slaver_pool to working_pool
        self.working_pool[addr_slaver] = self.spare_slaver_pool.pop(addr_slaver)
        self.working_pool[addr_slaver]['conn_slaver'] = actual_conn

        # ----------- connecting to target ----------
        try:
            conn_target = self._connect_target()
        except:
            log.error("unable to connect target")
            try_close(actual_conn)

            del self.working_pool[addr_slaver]
            return
        self.working_pool[addr_slaver]["conn_target"] = conn_target

        # ----------- all preparation finished -----------
        # pass two sockets to SocketBridge, and let it do the
        #   real data exchange task
        try:
            self.socket_bridge.add_conn_pair(
                actual_conn, conn_target,
                functools.partial(
                    # 这个回调用来在传输完成后删除工作池中对应记录
                    self._transfer_complete, addr_slaver
                )
            )
        except:
            log.error('error adding to socket_bridge', exc_info=True)
            try_close(actual_conn)
            try_close(conn_target)

        # this slaver thread exits here
        return

    def serve_forever(self):
        self.socket_bridge.start_as_daemon()  # hi, don't ignore me

        # sleep between two retries if exception occurs
        #   eg: master down or network temporary failed
        # err_delay would increase if err occurs repeatedly
        #   until `max_err_delay`
        # would immediately decrease to 0 after a success connection
        err_delay = 0
        max_err_delay = 15
        # spare_delay is sleep cycle if we are full of spare slaver
        #   would immediately decrease to 0 after a slaver lack
        spare_delay = 0.08
        default_spare_delay = 0.08

        while True:
            if len(self.spare_slaver_pool) >= self.max_spare_count:
                time.sleep(spare_delay)
                spare_delay = (spare_delay + default_spare_delay) / 2.0
                continue
            else:
                spare_delay = 0.0

            try:
                conn_slaver = self._connect_master()
            except Exception as e:
                log.warning("unable to connect master {}".format(e), exc_info=True)
                time.sleep(err_delay)
                if err_delay < max_err_delay:
                    err_delay += 1
                continue

            try:
                t = threading.Thread(target=self._slaver_working,
                                     args=(conn_slaver,)
                                     )
                t.daemon = True
                t.start()

                log.info("connected to master[{}] at {} total: {}".format(
                    fmt_addr(conn_slaver.getpeername()),
                    fmt_addr(conn_slaver.getsockname()),
                    len(self.spare_slaver_pool),
                ))
            except Exception as e:
                log.error("unable create Thread: {}".format(e))
                log.debug(traceback.format_exc())
                time.sleep(err_delay)

                if err_delay < max_err_delay:
                    err_delay += 1
                continue

            # set err_delay if everything is ok
            err_delay = 0


def run_slaver(communicate_addr, target_addr, max_spare_count=5, ssl=False):
    log.info("running as slaver, master addr: {} target: {}".format(
        fmt_addr(communicate_addr), fmt_addr(target_addr)
    ))

    Slaver(communicate_addr, target_addr,
           max_spare_count=max_spare_count,
           ssl=ssl,
           ).serve_forever()


def argparse_slaver():
    import argparse
    parser = argparse.ArgumentParser(
        description="""shootback {ver}-slaver
A fast and reliable reverse TCP tunnel (this is slaver)
Help access local-network service from Internet.
https://github.com/aploium/shootback""".format(ver=version_info()),
        epilog="""
Example1:
tunnel local ssh to public internet, assume master's ip is 1.2.3.4
  Master(another public server):  master.py -m 0.0.0.0:10000 -c 0.0.0.0:10022
  Slaver(this pc):                slaver.py -m 1.2.3.4:10000 -t 127.0.0.1:22
  Customer(any internet user):    ssh 1.2.3.4 -p 10022
  the actual traffic is:  customer <--> master(1.2.3.4) <--> slaver(this pc) <--> ssh(this pc)

Example2:
Tunneling for www.example.com
  Master(this pc):                master.py -m 127.0.0.1:10000 -c 127.0.0.1:10080
  Slaver(this pc):                slaver.py -m 127.0.0.1:10000 -t example.com:80
  Customer(this pc):              curl -v -H "host: example.com" 127.0.0.1:10080

Tips: ANY service using TCP is shootback-able.  HTTP/FTP/Proxy/SSH/VNC/...
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-m", "--master", required=True,
                        metavar="host:port",
                        help="master address, usually an Public-IP. eg: 2.3.3.3:5500")
    parser.add_argument("-t", "--target", required=True,
                        metavar="host:port",
                        help="where the traffic from master should be tunneled to, usually not public. eg: 10.1.2.3:80")
    parser.add_argument("-k", "--secretkey", default="shootback",
                        help="secretkey to identity master and slaver, should be set to the same value in both side")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="verbose output")
    parser.add_argument("-q", "--quiet", action="count", default=0,
                        help="quiet output, only display warning and errors, use two to disable output")
    parser.add_argument("-V", "--version", action="version", version="shootback {}-slaver".format(version_info()))
    parser.add_argument("--ttl", default=300, type=int, dest="SPARE_SLAVER_TTL",
                        help="standing-by slaver's TTL, default is 300. "
                             "this value is optimized for most cases")
    parser.add_argument("--max-standby", default=5, type=int, dest="max_spare_count",
                        help="max standby slaver TCP connections count, default is 5. "
                             "which is enough for more than 800 concurrency. "
                             "while working connections are always unlimited")
    parser.add_argument('--ssl', action='store_true', help='[experimental] try using ssl for data encryption. '
                                                           'It may be enabled by default in future version')

    return parser.parse_args()


def main_slaver():
    global SPARE_SLAVER_TTL

    args = argparse_slaver()

    if args.verbose and args.quiet:
        print("-v and -q should not appear together")
        exit(1)
        
    #A�adido por Virginia para cambiar el nombre del proceso  
    setproctitle.setproctitle('tunelTCP_'+args.master+"_"+args.target)

    communicate_addr = split_host(args.master)
    target_addr = split_host(args.target)

    set_secretkey(args.secretkey)

    SPARE_SLAVER_TTL = args.SPARE_SLAVER_TTL
    max_spare_count = args.max_spare_count
    if args.quiet < 2:
        if args.verbose:
            level = logging.DEBUG
        elif args.quiet:
            level = logging.WARNING
        else:
            level = logging.INFO
        configure_logging(level)

    log.info("shootback {} slaver running".format(version_info()))
    log.info("author: {}  site: {}".format(__author__, __website__))
    log.info("Master: {}".format(fmt_addr(communicate_addr)))
    log.info("Target: {}".format(fmt_addr(target_addr)))

    # communicate_addr = ("localhost", 12345)
    # target_addr = ("93.184.216.34", 80)  # www.example.com

    run_slaver(communicate_addr, target_addr,
               max_spare_count=max_spare_count,
               ssl=args.ssl,
               )


if __name__ == '__main__':
    main_slaver()
