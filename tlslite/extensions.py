# Copyright (c) 2014, 2015 Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

""" Helper package for handling TLS extensions encountered in ClientHello
and ServerHello messages.
"""

from __future__ import generators
from .utils.codec import Writer, Parser
from collections import namedtuple
from .constants import NameType, ExtensionType, CertificateStatusType
from .errors import TLSInternalError

class TLSExtension(object):
    """
    Base class for handling handshake protocol hello messages extensions.

    This class handles the generic information about TLS extensions used by
    both sides of connection in Client Hello and Server Hello messages.
    See U{RFC 4366<https://tools.ietf.org/html/rfc4366>} for more info.

    It is used as a base class for specific users and as a way to store
    extensions that are not implemented in library.

    To implement a new extension you will need to create a new class which
    calls this class contructor (__init__), usually specifying just the
    extType parameter. The other methods which need to be implemented are:
    L{extData}, L{create}, L{parse} and L{__repr__}. If the parser can be used
    for client and optionally server extensions, the extension constructor
    should be added to L{_universalExtensions}. Otherwise, when the client and
    server extensions have completely different forms, you should add client
    form to the L{_universalExtensions} and the server form to
    L{_serverExtensions}. Since the server MUST NOT send extensions not
    advertised by client, there are no purely server-side extensions. But
    if the client side extension is just marked by presence and has no payload,
    the client side (thus the L{_universalExtensions} may be skipped, then
    the L{TLSExtension} class will be used for implementing it. See
    end of the file for type-to-constructor bindings.

    Though please note that subclassing for the purpose of parsing extensions
    is not an officially supported part of API (just as underscores in their
    names would indicate.

    @type extType: int
    @ivar extType: a 2^16-1 limited integer specifying the type of the
        extension that it contains, e.g. 0 indicates server name extension

    @type extData: bytearray
    @ivar extData: a byte array containing the value of the extension as
        to be written on the wire

    @type serverType: boolean
    @ivar serverType: indicates that the extension was parsed with ServerHello
        specific parser, otherwise it used universal or ClientHello specific
        parser

    @type _universalExtensions: dict
    @cvar _universalExtensions: dictionary with concrete implementations of
        specific TLS extensions where key is the numeric value of the extension
        ID. Contains ClientHello version of extensions or universal
        implementations

    @type _serverExtensions: dict
    @cvar _serverExtensions: dictionary with concrete implementations of
        specific TLS extensions where key is the numeric value of the extension
        ID. Includes only those extensions that require special handlers for
        ServerHello versions.
    """
    # actual definition at the end of file, after definitions of all classes
    _universalExtensions = {}
    _serverExtensions = {}

    def __init__(self, server=False, extType=None):
        """
        Creates a generic TLS extension.

        You'll need to use L{create} or L{parse} methods to create an extension
        that is actually usable.

        @type server: boolean
        @param server: whether to select ClientHello or ServerHello version
            for parsing
        @type extType: int
        @param extType: type of extension encoded as an integer, to be used
            by subclasses
        """
        self.extType = extType
        self._extData = bytearray(0)
        self.serverType = server

    @property
    def extData(self):
        """
        Return the on the wire encoding of extension

        Child classes need to override this property so that it returns just
        the payload of an extension, that is, without the 4 byte generic header
        common to all extension. In other words, without the extension ID and
        overall extension length.

        @rtype: bytearray
        """
        return self._extData

    def _oldCreate(self, extType, data):
        """Legacy handling of create method"""
        self.extType = extType
        self._extData = data

    def _newCreate(self, data):
        """New format for create method"""
        self._extData = data

    def create(self, *args, **kwargs):
        """
        Initializes a generic TLS extension.

        The extension can carry arbitrary data and have arbitrary payload, can
        be used in client hello or server hello messages.

        The legacy calling method uses two arguments - the extType and data.
        If the new calling method is used, only one argument is passed in -
        data.

        Child classes need to override this method so that it is possible
        to set values for all fields used by the extension.

        @type  extType: int
        @param extType: if int: type of the extension encoded as an integer
            between M{0} and M{2^16-1}
        @type  data: bytearray
        @param data: raw data representing extension on the wire
        @rtype: L{TLSExtension}
        """
        # old style
        if len(args) + len(kwargs) == 2:
            self._oldCreate(*args, **kwargs)
        # new style
        elif len(args) + len(kwargs) == 1:
            self._newCreate(*args, **kwargs)
        else:
            raise TypeError("Invalid number of arguments")

        return self

    def write(self):
        """Returns encoded extension, as encoded on the wire

        Note that child classes in general don't need to override this method.

        @rtype: bytearray
        @return: An array of bytes formatted as is supposed to be written on
           the wire, including the extension_type, length and the extension
           data

        @raise AssertionError: when the object was not initialized
        """
        assert self.extType is not None

        w = Writer()
        w.addTwo(self.extType)
        data = self.extData
        w.addTwo(len(data))
        w.bytes += data
        return w.bytes

    @staticmethod
    def _parseExt(parser, extType, extLength, extList):
        """Parse a extension using a predefined constructor"""
        ext = extList[extType]()
        extParser = Parser(parser.getFixBytes(extLength))
        ext = ext.parse(extParser)
        return ext

    def parse(self, p):
        """Parses extension from on the wire format

        Child classes should override this method so that it parses the
        extension from on the wire data. Note that child class parsers will
        not receive the generic header of the extension, but just a parser
        with the payload. In other words, the method should be the exact
        reverse of the L{extData} property.

        @type p: L{tlslite.util.codec.Parser}
        @param p:  data to be parsed

        @raise SyntaxError: when the size of the passed element doesn't match
        the internal representation

        @rtype: L{TLSExtension}
        """
        extType = p.get(2)
        extLength = p.get(2)

        # first check if we shouldn't use server side parser
        if self.serverType and extType in self._serverExtensions:
            return self._parseExt(p, extType, extLength,
                                  self._serverExtensions)

        # then fallback to universal/ClientHello-specific parsers
        if extType in self._universalExtensions:
            return self._parseExt(p, extType, extLength,
                                  self._universalExtensions)

        # finally, just save the extension data as there are extensions which
        # don't require specific handlers and indicate option by mere presence
        self.extType = extType
        self._extData = p.getFixBytes(extLength)
        assert len(self._extData) == extLength
        return self

    def __eq__(self, that):
        """Test if two TLS extensions are effectively the same

        Will check if encoding them will result in the same on the wire
        representation.

        Will return False for every object that's not an extension.
        """
        if hasattr(that, 'extType') and hasattr(that, 'extData'):
            return self.extType == that.extType and \
                    self.extData == that.extData
        else:
            return False

    def __repr__(self):
        """Output human readable representation of object

        Child classes should override this method to support more appropriate
        string rendering of the extension.

        @rtype: str
        """
        return "TLSExtension(extType={0!r}, extData={1!r},"\
                " serverType={2!r})".format(self.extType, self.extData,
                                            self.serverType)

class VarListExtension(TLSExtension):
    """
    Abstract extension for handling extensions comprised only of a value list

    Extension for handling arbitrary extensions comprising of just a list
    of same-sized elementes inside an array
    """

    def __init__(self, elemLength, lengthLength, fieldName, extType):
        super(VarListExtension, self).__init__(extType=extType)
        self._fieldName = fieldName
        self._internalList = None
        self._elemLength = elemLength
        self._lengthLength = lengthLength

    @property
    def extData(self):
        """Return raw data encoding of the extension

        @rtype: bytearray
        """
        if self._internalList is None:
            return bytearray(0)

        writer = Writer()
        writer.addVarSeq(self._internalList,
                         self._elemLength,
                         self._lengthLength)
        return writer.bytes

    def create(self, values):
        """Set the list to specified values

        @type values: list of int
        @param values: list of values to save
        """
        self._internalList = values
        return self

    def parse(self, parser):
        """
        Deserialise extension from on-the-wire data

        @type parser: L{Parser}
        @rtype: Extension
        """
        if parser.getRemainingLength() == 0:
            self._internalList = None
            return self

        self._internalList = parser.getVarList(self._elemLength,
                                               self._lengthLength)
        return self

    def __getattr__(self, name):
        """Return the special field name value"""
        if name == '_fieldName':
            raise AttributeError("type object '{0}' has no attribute '{1}'"\
                    .format(self.__class__.__name__, name))
        if name == self._fieldName:
            return self._internalList
        raise AttributeError("type object '{0}' has no attribute '{1}'"\
                .format(self.__class__.__name__, name))

    def __setattr__(self, name, value):
        """Set the special field value"""
        if name == '_fieldName':
            super(VarListExtension, self).__setattr__(name, value)
            return
        if hasattr(self, '_fieldName') and name == self._fieldName:
            self._internalList = value
            return
        super(VarListExtension, self).__setattr__(name, value)

    def __repr__(self):
        return "{0}({1}={2!r})".format(self.__class__.__name__,
                                       self._fieldName,
                                       self._internalList)

class SNIExtension(TLSExtension):
    """
    Class for handling Server Name Indication (server_name) extension from
    RFC 4366.

    Note that while usually the client does advertise just one name, it is
    possible to provide a list of names, each of different type.
    The type is a single byte value (represented by ints), the names are
    opaque byte strings, in case of DNS host names (records of type 0) they
    are UTF-8 encoded domain names (without the ending dot).

    @type hostNames: tuple of bytearrays
    @ivar hostNames: tuple of hostnames (server name records of type 0)
        advertised in the extension. Note that it may not include all names
        from client hello as the client can advertise other types. Also note
        that while it's not possible to change the returned array in place, it
        is possible to assign a new set of names. IOW, this won't work::

           sni_extension.hostNames[0] = bytearray(b'example.com')

        while this will work::

           names = list(sni_extension.hostNames)
           names[0] = bytearray(b'example.com')
           sni_extension.hostNames = names


    @type serverNames: list of L{ServerName}
    @ivar serverNames: list of all names advertised in extension.
        L{ServerName} is a namedtuple with two elements, the first
        element (type) defines the type of the name (encoded as int)
        while the other (name) is a bytearray that carries the value.
        Known types are defined in L{tlslite.constants.NameType}.
        The list will be empty if the on the wire extension had and empty
        list while it will be None if the extension was empty.

    @type extType: int
    @ivar extType: numeric type of SNIExtension, i.e. 0

    @type extData: bytearray
    @ivar extData: raw representation of the extension
    """

    ServerName = namedtuple('ServerName', 'name_type name')

    def __init__(self):
        """
        Create an instance of SNIExtension.

        See also: L{create} and L{parse}.
        """
        super(SNIExtension, self).__init__(extType=ExtensionType.server_name)
        self.serverNames = None

    def __repr__(self):
        """
        Return programmer-readable representation of extension

        @rtype: str
        """
        return "SNIExtension(serverNames={0!r})".format(self.serverNames)

    def create(self, hostname=None, hostNames=None, serverNames=None):
        """
        Initializes an instance with provided hostname, host names or
        raw server names.

        Any of the parameters may be None, in that case the list inside the
        extension won't be defined, if either hostNames or serverNames is
        an empty list, then the extension will define a list of lenght 0.

        If multiple parameters are specified at the same time, then the
        resulting list of names will be concatenated in order of hostname,
        hostNames and serverNames last.

        @type  hostname: bytearray
        @param hostname: raw UTF-8 encoding of the host name

        @type  hostNames: list of bytearrays
        @param hostNames: list of raw UTF-8 encoded host names

        @type  serverNames: list of L{ServerName}
        @param serverNames: pairs of name_type and name encoded as a namedtuple

        @rtype: L{SNIExtension}
        """
        if hostname is None and hostNames is None and serverNames is None:
            self.serverNames = None
            return self
        else:
            self.serverNames = []

        if hostname:
            self.serverNames += [SNIExtension.ServerName(NameType.host_name,\
                    hostname)]

        if hostNames:
            self.serverNames +=\
                    [SNIExtension.ServerName(NameType.host_name, x) for x in\
                    hostNames]

        if serverNames:
            self.serverNames += serverNames

        return self

    @property
    def hostNames(self):
        """ Returns a simulated list of hostNames from the extension.

        @rtype: tuple of bytearrays
        """
        # because we can't simulate assignments to array elements we return
        # an immutable type
        if self.serverNames is None:
            return tuple()
        else:
            return tuple([x.name for x in self.serverNames if \
                x.name_type == NameType.host_name])

    @hostNames.setter
    def hostNames(self, hostNames):
        """ Removes all host names from the extension and replaces them by
        names in X{hostNames} parameter.

        Newly added parameters will be added at the I{beginning} of the list
        of extensions.

        @type hostNames: iterable of bytearrays
        @param hostNames: host names to replace the old server names of type 0
        """

        self.serverNames = \
                [SNIExtension.ServerName(NameType.host_name, x) for x in \
                    hostNames] + \
                [x for x in self.serverNames if \
                    x.name_type != NameType.host_name]

    @hostNames.deleter
    def hostNames(self):
        """ Remove all host names from extension, leaves other name types
        unmodified
        """
        self.serverNames = [x for x in self.serverNames if \
                x.name_type != NameType.host_name]

    @property
    def extData(self):
        """ raw encoding of extension data, without type and length header

        @rtype: bytearray
        """
        if self.serverNames is None:
            return bytearray(0)

        w2 = Writer()
        for server_name in self.serverNames:
            w2.add(server_name.name_type, 1)
            w2.add(len(server_name.name), 2)
            w2.bytes += server_name.name

        # note that when the array is empty we write it as array of length 0
        w = Writer()
        w.add(len(w2.bytes), 2)
        w.bytes += w2.bytes
        return w.bytes

    def write(self):
        """ Returns encoded extension, as encoded on the wire

        @rtype: bytearray
        @return: an array of bytes formatted as they are supposed to be written
            on the wire, including the type, length and extension data
        """

        raw_data = self.extData

        w = Writer()
        w.add(self.extType, 2)
        w.add(len(raw_data), 2)
        w.bytes += raw_data

        return w.bytes

    def parse(self, p):
        """
        Deserialise the extension from on-the-wire data

        The parser should not include the type or length of extension!

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @rtype: L{SNIExtension}
        @raise SyntaxError: when the internal sizes don't match the attached
            data
        """
        if p.getRemainingLength() == 0:
            return self

        self.serverNames = []

        p.startLengthCheck(2)
        while not p.atLengthCheck():
            sn_type = p.get(1)
            sn_name = p.getVarBytes(2)
            self.serverNames += [SNIExtension.ServerName(sn_type, sn_name)]
        p.stopLengthCheck()

        return self

class ClientCertTypeExtension(VarListExtension):
    """
    This class handles the (client variant of) Certificate Type extension

    See RFC 6091.

    @type extType: int
    @ivar extType: numeric type of Certificate Type extension, i.e. 9

    @type extData: bytearray
    @ivar extData: raw representation of the extension data

    @type certTypes: list of int
    @ivar certTypes: list of certificate type identifiers (each one byte long)
    """

    def __init__(self):
        """
        Create an instance of ClientCertTypeExtension

        See also: L{create} and L{parse}
        """
        super(ClientCertTypeExtension, self).__init__(1, 1, 'certTypes', \
                ExtensionType.cert_type)

class ServerCertTypeExtension(TLSExtension):
    """
    This class handles the Certificate Type extension (variant sent by server)
    defined in RFC 6091.

    @type extType: int
    @ivar extType: binary type of Certificate Type extension, i.e. 9

    @type extData: bytearray
    @ivar extData: raw representation of the extension data

    @type cert_type: int
    @ivar cert_type: the certificate type selected by server
    """

    def __init__(self):
        """
        Create an instance of ServerCertTypeExtension

        See also: L{create} and L{parse}
        """
        super(ServerCertTypeExtension, self).__init__(server=True, \
                                               extType=ExtensionType.cert_type)
        self.cert_type = None

    def __repr__(self):
        """ Return programmer-centric description of object

        @rtype: str
        """
        return "ServerCertTypeExtension(cert_type={0!r})".format(self.cert_type)

    @property
    def extData(self):
        """
        Return the raw encoding of the extension data

        @rtype: bytearray
        """
        if self.cert_type is None:
            return bytearray(0)

        w = Writer()
        w.add(self.cert_type, 1)

        return w.bytes

    def create(self, val):
        """Create an instance for sending the extension to client.

        @type val: int
        @param val: selected type of certificate
        """
        self.cert_type = val
        return self

    def parse(self, p):
        """Parse the extension from on the wire format

        @type p: L{Parser}
        @param p: parser with data
        """
        self.cert_type = p.get(1)
        if p.getRemainingLength() > 0:
            raise SyntaxError()

        return self

class SRPExtension(TLSExtension):
    """
    This class handles the Secure Remote Password protocol TLS extension
    defined in RFC 5054.

    @type extType: int
    @ivar extType: numeric type of SRPExtension, i.e. 12

    @type extData: bytearray
    @ivar extData: raw representation of extension data

    @type identity: bytearray
    @ivar identity: UTF-8 encoding of user name
    """

    def __init__(self):
        """
        Create an instance of SRPExtension

        See also: L{create} and L{parse}
        """
        super(SRPExtension, self).__init__(extType=ExtensionType.srp)

        self.identity = None

    def __repr__(self):
        """
        Return programmer-centric description of extension

        @rtype: str
        """
        return "SRPExtension(identity={0!r})".format(self.identity)

    @property
    def extData(self):
        """
        Return raw data encoding of the extension

        @rtype: bytearray
        """

        if self.identity is None:
            return bytearray(0)

        w = Writer()
        w.add(len(self.identity), 1)
        w.addFixSeq(self.identity, 1)

        return w.bytes

    def create(self, identity=None):
        """ Create and instance of SRPExtension with specified protocols

        @type identity: bytearray
        @param identity: UTF-8 encoded identity (user name) to be provided
            to user. MUST be shorter than 2^8-1.

        @raise ValueError: when the identity lenght is longer than 2^8-1
        """

        if identity is None:
            return self

        if len(identity) >= 2**8:
            raise ValueError()

        self.identity = identity
        return self

    def parse(self, p):
        """
        Parse the extension from on the wire format

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @raise SyntaxError: when the data is internally inconsistent

        @rtype: L{SRPExtension}
        """

        self.identity = p.getVarBytes(1)

        return self

class NPNExtension(TLSExtension):
    """
    This class handles the unofficial Next Protocol Negotiation TLS extension.

    @type protocols: list of bytearrays
    @ivar protocols: list of protocol names supported by the server

    @type extType: int
    @ivar extType: numeric type of NPNExtension, i.e. 13172

    @type extData: bytearray
    @ivar extData: raw representation of extension data
    """

    def __init__(self):
        """
        Create an instance of NPNExtension

        See also: L{create} and L{parse}
        """
        super(NPNExtension, self).__init__(extType=ExtensionType.supports_npn)

        self.protocols = None

    def __repr__(self):
        """
        Create programmer-readable version of representation

        @rtype: str
        """
        return "NPNExtension(protocols={0!r})".format(self.protocols)

    @property
    def extData(self):
        """ Return the raw data encoding of the extension

        @rtype: bytearray
        """
        if self.protocols is None:
            return bytearray(0)

        w = Writer()
        for prot in self.protocols:
            w.add(len(prot), 1)
            w.addFixSeq(prot, 1)

        return w.bytes

    def create(self, protocols=None):
        """ Create an instance of NPNExtension with specified protocols

        @type protocols: list of bytearray
        @param protocols: list of protocol names that are supported
        """
        self.protocols = protocols
        return self

    def parse(self, p):
        """ Parse the extension from on the wire format

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @raise SyntaxError: when the size of the passed element doesn't match
            the internal representation

        @rtype: L{NPNExtension}
        """
        self.protocols = []

        while p.getRemainingLength() > 0:
            self.protocols += [p.getVarBytes(1)]

        return self

class TACKExtension(TLSExtension):
    """
    This class handles the server side TACK extension (see
    draft-perrin-tls-tack-02).

    @type tacks: list
    @ivar tacks: list of L{TACK}'s supported by server

    @type activation_flags: int
    @ivar activation_flags: activation flags for the tacks
    """

    class TACK(object):
        """
        Implementation of the single TACK
        """
        def __init__(self):
            """
            Create a single TACK object
            """
            self.public_key = bytearray(64)
            self.min_generation = 0
            self.generation = 0
            self.expiration = 0
            self.target_hash = bytearray(32)
            self.signature = bytearray(64)

        def __repr__(self):
            """
            Return programmmer readable representation of TACK object

            @rtype: str
            """
            return "TACK(public_key={0!r}, min_generation={1!r}, "\
                    "generation={2!r}, expiration={3!r}, target_hash={4!r}, "\
                    "signature={5!r})".format(
                            self.public_key, self.min_generation,
                            self.generation, self.expiration, self.target_hash,
                            self.signature)

        def create(self, public_key, min_generation, generation, expiration,
                target_hash, signature):
            """
            Initialise the TACK with data
            """
            self.public_key = public_key
            self.min_generation = min_generation
            self.generation = generation
            self.expiration = expiration
            self.target_hash = target_hash
            self.signature = signature
            return self

        def write(self):
            """
            Convert the TACK into on the wire format

            @rtype: bytearray
            """
            w = Writer()
            if len(self.public_key) != 64:
                raise TLSInternalError("Public_key must be 64 bytes long")
            w.bytes += self.public_key
            w.add(self.min_generation, 1)
            w.add(self.generation, 1)
            w.add(self.expiration, 4)
            if len(self.target_hash) != 32:
                raise TLSInternalError("Target_hash must be 32 bytes long")
            w.bytes += self.target_hash
            if len(self.signature) != 64:
                raise TLSInternalError("Signature must be 64 bytes long")
            w.bytes += self.signature
            return w.bytes

        def parse(self, p):
            """
            Parse the TACK from on the wire format

            @type p: L{tlslite.util.codec.Parser}
            @param p: data to be parsed

            @rtype: L{TACK}
            @raise SyntaxError: when the internal sizes don't match the
                provided data
            """

            self.public_key = p.getFixBytes(64)
            self.min_generation = p.get(1)
            self.generation = p.get(1)
            self.expiration = p.get(4)
            self.target_hash = p.getFixBytes(32)
            self.signature = p.getFixBytes(64)
            return self

        def __eq__(self, other):
            """
            Tests if the other object is equivalent to this TACK

            Returns False for every object that's not a TACK
            """
            if hasattr(other, 'public_key') and\
                    hasattr(other, 'min_generation') and\
                    hasattr(other, 'generation') and\
                    hasattr(other, 'expiration') and\
                    hasattr(other, 'target_hash') and\
                    hasattr(other, 'signature'):
                if self.public_key == other.public_key and\
                   self.min_generation == other.min_generation and\
                   self.generation == other.generation and\
                   self.expiration == other.expiration and\
                   self.target_hash == other.target_hash and\
                   self.signature == other.signature:
                    return True
                else:
                    return False
            else:
                return False

    def __init__(self):
        """
        Create an instance of TACKExtension

        See also: L{create} and L{parse}
        """
        super(TACKExtension, self).__init__(extType=ExtensionType.tack)

        self.tacks = []
        self.activation_flags = 0

    def __repr__(self):
        """
        Create a programmer readable representation of TACK extension

        @rtype: str
        """
        return "TACKExtension(activation_flags={0!r}, tacks={1!r})".format(
                self.activation_flags, self.tacks)

    @property
    def extData(self):
        """
        Return the raw data encoding of the extension

        @rtype: bytearray
        """
        w2 = Writer()
        for t in self.tacks:
            w2.bytes += t.write()

        w = Writer()
        w.add(len(w2.bytes), 2)
        w.bytes += w2.bytes
        w.add(self.activation_flags, 1)
        return w.bytes

    def create(self, tacks, activation_flags):
        """
        Initialize the instance of TACKExtension

        @rtype: TACKExtension
        """

        self.tacks = tacks
        self.activation_flags = activation_flags
        return self

    def parse(self, p):
        """
        Parse the extension from on the wire format

        @type p: L{tlslite.util.codec.Parser}
        @param p: data to be parsed

        @rtype: L{TACKExtension}
        """
        self.tacks = []

        p.startLengthCheck(2)
        while not p.atLengthCheck():
            tack = TACKExtension.TACK().parse(p)
            self.tacks += [tack]
        p.stopLengthCheck()
        self.activation_flags = p.get(1)

        return self

class SupportedGroupsExtension(VarListExtension):
    """
    Client side list of supported groups of (EC)DHE key exchage.

    See RFC4492, RFC7027 and RFC-ietf-tls-negotiated-ff-dhe-10

    @type groups: int
    @ivar groups: list of groups that the client supports
    """

    def __init__(self):
        """Create instance of class"""
        super(SupportedGroupsExtension, self).__init__(2, 2, 'groups', \
            ExtensionType.supported_groups)

class ECPointFormatsExtension(VarListExtension):
    """
    Client side list of supported ECC point formats.

    See RFC4492.

    @type formats: list of int
    @ivar formats: list of point formats supported by peer
    """

    def __init__(self):
        """Create instance of class"""
        super(ECPointFormatsExtension, self).__init__(1, 1, 'formats', \
                ExtensionType.ec_point_formats)

class SignatureAlgorithmsExtension(TLSExtension):

    """
    Client side list of supported signature algorithms.

    Should be used by server to select certificate and signing method for
    Server Key Exchange messages. In practice used only for the latter.

    See RFC5246.
    """

    def __init__(self):
        """Create instance of class"""
        super(SignatureAlgorithmsExtension, self).__init__(extType=
                                                           ExtensionType.
                                                           signature_algorithms)
        self.sigalgs = None

    @property
    def extData(self):
        """
        Return raw encoding of the extension

        @rtype: bytearray
        """
        if self.sigalgs is None:
            return bytearray(0)

        writer = Writer()
        # elements 1 byte each, overall length encoded in 2 bytes
        writer.addVarTupleSeq(self.sigalgs, 1, 2)
        return writer.bytes

    def create(self, sigalgs):
        """
        Set the list of supported algorithm types

        @type sigalgs: list of tuples
        @param sigalgs: list of pairs of a hash algorithm and signature
        algorithm
        """
        self.sigalgs = sigalgs
        return self

    def parse(self, parser):
        """
        Deserialise extension from on the wire data

        @type parser: L{Parser}
        @rtype: SignatureAlgorithmsExtension
        """
        if parser.getRemainingLength() == 0:
            self.sigalgs = None
            return self

        self.sigalgs = parser.getVarTupleList(1, 2, 2)

        if parser.getRemainingLength() != 0:
            raise SyntaxError()

        return self


class PaddingExtension(TLSExtension):
    """
    ClientHello message padding with a desired size.

    Can be used to pad ClientHello messages to a desired size
    in order to avoid implementation bugs caused by certain
    ClientHello sizes.

    See RFC7685.
    """

    def __init__(self):
        """Create instance of class."""
        extType = ExtensionType.client_hello_padding
        super(PaddingExtension, self).__init__(extType=extType)
        self.paddingData = bytearray(0)

    @property
    def extData(self):
        """
        Return raw encoding of the extension.

        @rtype: bytearray
        """
        return self.paddingData

    def create(self, size):
        """
        Set the padding size and create null byte padding of defined size.

        @type size: int
        @param size: required padding size in bytes
        """
        self.paddingData = bytearray(size)
        return self

    def parse(self, p):
        """
        Deserialise extension from on the wire data.

        @type p: L{tlslite.util.codec.Parser}
        @param p:  data to be parsed

        @raise SyntaxError: when the size of the passed element doesn't match
        the internal representation

        @rtype: L{TLSExtension}
        """
        self.paddingData = p.getFixBytes(p.getRemainingLength())
        return self

class RenegotiationInfoExtension(TLSExtension):
    """
    Client and Server Hello secure renegotiation extension from RFC 5746

    Should have an empty renegotiated_connection field in case of initial
    connection
    """

    def __init__(self):
        """Create instance"""
        extType = ExtensionType.renegotiation_info
        super(RenegotiationInfoExtension, self).__init__(extType=extType)
        self.renegotiated_connection = None

    @property
    def extData(self):
        """
        Return raw encoding of the extension.

        @rtype: bytearray
        """
        if self.renegotiated_connection is None:
            return bytearray(0)
        writer = Writer()
        writer.add(len(self.renegotiated_connection), 1)
        writer.bytes += self.renegotiated_connection
        return writer.bytes

    def create(self, renegotiated_connection):
        """
        Set the finished message payload from previous connection.

        @type renegotiated_connection: bytearray
        """
        self.renegotiated_connection = renegotiated_connection
        return self

    def parse(self, parser):
        """
        Deserialise extension from on the wire data.

        @type parser: L{tlslite.util.codec.Parser}
        @param parser: data to be parsed

        @rtype: L{RenegotiationInfoExtension}
        """
        if parser.getRemainingLength() == 0:
            self.renegotiated_connection = None
        else:
            self.renegotiated_connection = parser.getVarBytes(1)

        return self


class ALPNExtension(TLSExtension):
    """
    Handling of Application Layer Protocol Negotiation extension from RFC 7301.

    @type protocol_names: list of bytearrays
    @ivar protocol_names: list of protocol names acceptable or selected by peer

    @type extType: int
    @ivar extType: numberic type of ALPNExtension, i.e. 16

    @type extData: bytearray
    @ivar extData: raw encoding of the extension data
    """

    def __init__(self):
        """
        Create instance of ALPNExtension

        See also: L{create} and L{parse}
        """
        super(ALPNExtension, self).__init__(extType=ExtensionType.alpn)

        self.protocol_names = None

    def __repr__(self):
        """
        Create programmer-readable representation of object

        @rtype: str
        """
        return "ALPNExtension(protocol_names={0!r})".format(self.protocol_names)

    @property
    def extData(self):
        """
        Return encoded payload of the extension

        @rtype: bytearray
        """
        if self.protocol_names is None:
            return bytearray(0)

        writer = Writer()
        for prot in self.protocol_names:
            writer.add(len(prot), 1)
            writer.bytes += prot

        writer2 = Writer()
        writer2.add(len(writer.bytes), 2)
        writer2.bytes += writer.bytes

        return writer2.bytes

    def create(self, protocol_names=None):
        """
        Create an instance of ALPNExtension with specified protocols

        @type protocols: list of bytearray
        @param protocols: list of protocol names that are to be sent
        """
        self.protocol_names = protocol_names
        return self

    def parse(self, parser):
        """
        Parse the extension from on the wire format

        @type parser: L{tlslite.util.codec.Parser}
        @param parser: data to be parsed as extension

        @raise SyntaxError: when the encoding of the extension is self
            inconsistent

        @rtype: L{ALPNExtension}
        """
        self.protocol_names = []
        parser.startLengthCheck(2)
        while not parser.atLengthCheck():
            name_len = parser.get(1)
            self.protocol_names.append(parser.getFixBytes(name_len))
        parser.stopLengthCheck()
        if parser.getRemainingLength() != 0:
            raise SyntaxError("Trailing data after protocol_name_list")
        return self


class StatusRequestExtension(TLSExtension):
    """
    Handling of the Certificate Status Request extension from RFC 6066.

    @type status_type: int
    @ivar status_type: type of the status request

    @type responder_id_list: list of bytearray
    @ivar responder_id_list: list of DER encoded OCSP responder identifiers
        that the client trusts

    @type request_extensions: bytearray
    @ivar request_extensions: DER encoded list of OCSP extensions, as defined
        in RFC 2560
    """

    def __init__(self):
        super(StatusRequestExtension, self).__init__(
                extType=ExtensionType.status_request)
        """Create instance of StatusRequestExtension."""
        self.status_type = None
        self.responder_id_list = []
        self.request_extensions = bytearray()

    def __repr__(self):
        """
        Create programmer-readable representation of object

        @rtype: str
        """
        return ("StatusRequestExtension(status_type={0}, "
                "responder_id_list={1!r}, "
                "request_extensions={2!r})").format(
                    self.status_type, self.responder_id_list,
                    self.request_extensions)

    @property
    def extData(self):
        """
        Return encoded payload of the extension.

        @rtype: bytearray
        """
        if self.status_type is None:
            return bytearray()

        writer = Writer()
        writer.add(self.status_type, 1)
        writer2 = Writer()
        for i in self.responder_id_list:
            writer2.add(len(i), 2)
            writer2.bytes += i
        writer.add(len(writer2.bytes), 2)
        writer.bytes += writer2.bytes
        writer.add(len(self.request_extensions), 2)
        writer.bytes += self.request_extensions

        return writer.bytes

    def create(self, status_type=CertificateStatusType.ocsp,
               responder_id_list=tuple(),
               request_extensions=b''):
        """
        Create an instance of StatusRequestExtension with specified options.

        @type status_type: int
        @param status_type: type of status returned

        @type responder_id_list: list
        @param responder_id_list: list of encoded OCSP responder identifiers
            that the client trusts

        @type request_extensions: bytearray
        @param request_extensions: DER encoding of requested OCSP extensions
        """
        self.status_type = status_type
        self.responder_id_list = list(responder_id_list)
        self.request_extensions = bytearray(request_extensions)
        return self

    def parse(self, parser):
        """
        Parse the extension from on the wire format.

        @type parser: L{tlslite.util.codec.Parser}
        @param parser: data to be parsed as extension

        @rtype: L{StatusRequestExtension}
        """
        # handling of server side message
        if parser.getRemainingLength() == 0:
            self.status_type = None
            self.responder_id_list = []
            self.request_extensions = bytearray()
            return self

        self.status_type = parser.get(1)
        self.responder_id_list = []
        parser.startLengthCheck(2)
        while not parser.atLengthCheck():
            self.responder_id_list.append(parser.getVarBytes(2))
        parser.stopLengthCheck()
        self.request_extensions = parser.getVarBytes(2)
        if parser.getRemainingLength() != 0:
            raise SyntaxError("Trailing data after CertificateStatusRequest")
        return self


class HeartbeatExtension(TLSExtension):
    """
    Heartbeat extension from RFC 6520

    @type mode: int
    @ivar mode: mode if peer is allowed or nor allowed to send responses
    """
    def __init__(self):
        super(HeartbeatExtension, self).__init__(
                                        extType=ExtensionType.heartbeat)
        self.mode = None

    @property
    def extData(self):
        """
        Return encoded heartbeat mode

        @rtype: bytearray
        """
        if self.mode is None:
            return bytearray(0)

        writer = Writer()
        writer.add(self.mode, 1)

        return writer.bytes

    def create(self, mode):
        self.mode = mode
        return self

    def parse(self, p):
        self.mode = p.get(1)
        if p.getRemainingLength() > 0:
            raise SyntaxError()

        return self

TLSExtension._universalExtensions = \
    {
        ExtensionType.server_name: SNIExtension,
        ExtensionType.status_request: StatusRequestExtension,
        ExtensionType.cert_type: ClientCertTypeExtension,
        ExtensionType.supported_groups: SupportedGroupsExtension,
        ExtensionType.ec_point_formats: ECPointFormatsExtension,
        ExtensionType.srp: SRPExtension,
        ExtensionType.signature_algorithms: SignatureAlgorithmsExtension,
        ExtensionType.alpn: ALPNExtension,
        ExtensionType.supports_npn: NPNExtension,
        ExtensionType.client_hello_padding: PaddingExtension,
        ExtensionType.renegotiation_info: RenegotiationInfoExtension,
        ExtensionType.heartbeat: HeartbeatExtension}

TLSExtension._serverExtensions = \
    {
        ExtensionType.cert_type: ServerCertTypeExtension,
        ExtensionType.tack: TACKExtension}
