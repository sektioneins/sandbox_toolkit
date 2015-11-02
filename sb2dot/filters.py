#
# sb2dot - a sandbox binary profile to dot convertor for iOS 9 and OS X 10.11
# Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>
#    uses and extends code from Dionysus Blazakis with his permission
#
# module: filters.py
# task: implements decoder for iOS / OS X sandbox filters 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import struct

class Terminal(object):
  def __init__(self, result):
    self.allow = (result & 1) == 0

    modifiers = []
    if (result & 2) == 2:
      modifiers.append("grant")
    if (result & 4) == 4:
      modifiers.append("report")
    if (result & 8) == 8:
      modifiers.append("no-callout")
    if (result & 16) == 16:
      modifiers.append("no-sandbox")
    if (result & 32) == 32:
      modifiers.append("partial-symbolication")
    self.modifiers = modifiers

  def __repr__(self):
    if self.allow:
      rv = 'allow'
    else:
      rv = 'deny'

    if len(self.modifiers) > 0:
      rv += ' (with %s)' % (' '.join(self.modifiers),)

    return rv


class StringFilter(object):
  def __init__(self, s):
    self.s = s

class LiteralFilter(StringFilter):
  def __repr__(self):
    return '(literal "%s")' % (self.s, )

class RegexFilter(StringFilter):
  def __repr__(self):
    return '(regex #"%s")' % (self.s, )

class MountRelativeRegexFilter(StringFilter):
  def __repr__(self):
    return '(mount-relative-regex #"%s")' % (self.s, )

class GlobalNameFilter(StringFilter):
  def __repr__(self):
    return '(global-name "%s")' % (self.s, )

class LocalNameFilter(StringFilter):
  def __repr__(self):
    return '(local-name "%s")' % (self.s, )

class MountRelativeFilter(StringFilter):
  def __repr__(self):
    return '(mount-relative-path "%s")' % (self.s, )

class IPCPosixFilter(StringFilter):
  def __repr__(self):
    return '(ipc-posix-name "%s")' % (self.s, )

class IPCPosixRegexFilter(StringFilter):
  def __repr__(self):
    return '(ipc-posix-name-regex #"%s")' % (self.s, )

class GlobalNameRegexFilter(StringFilter):
  def __repr__(self):
    return '(global-name-regex #"%s")' % (self.s, )

class LocalNameRegexFilter(StringFilter):
  def __repr__(self):
    return '(local-name-regex #"%s")' % (self.s, )
    
class IOKitFilter(StringFilter):
  def __repr__(self):
    return '(iokit-user-client-class "%s")' % (self.s, )

class IOKitConnectionFilter(StringFilter):
  def __repr__(self):
    return '(iokit-connection "%s")' % (self.s, )

class IOKitRegexFilter(StringFilter):
  def __repr__(self):
    return '(iokit-user-client-class-regex #"%s")' % (self.s, )

class ControlFilter(StringFilter):
  def __repr__(self):
    return '(control-name "%s")' % (self.s, )

class AppleeventDestinationFilter(StringFilter):
  def __repr__(self):
    return '(appleevent-destination "%s")' % (self.s, )


class PreferenceDomainFilter(StringFilter):
  def __repr__(self):
    return '(preference-domain "%s")' % (self.s, )

class NetworkFilter(object):
  def __init__(self, arg):
    typ, addr, port = arg

    if typ == 0x0b:
      self.typ = 'udp'
    elif typ == 0x07:
      self.typ = 'tcp'
    else:
      self.typ = 'unknown'

    if addr == 0:
      self.addr = '*'
    else:
      self.addr = 'localhost'

    if port == 0:
      self.port = '*'
    else:
      self.port = port

class LocalFilter(NetworkFilter):
  def __repr__(self):
    return '(local "%s:%s:%s")' % (self.typ, self.addr, self.port)

class RemoteFilter(NetworkFilter):
  def __repr__(self):
    return '(remote "%s:%s:%s")' % (self.typ, self.addr, self.port)

class ExtensionFilter(StringFilter):
  def __repr__(self):
    return '(extension "%s")' % (self.s, )

class DeviceConformsToFilter(StringFilter):
  def __repr__(self):
    return '(device-conforms-to "%s")' % (self.s, )

class ExtensionClassFilter(StringFilter):
  def __repr__(self):
    return '(extension-class "%s")' % (self.s, )

class RequireEntitlementFilter(StringFilter):
  def __repr__(self):
    return '(entitlement "%s")' % (self.s, )

class EntitlementStringCompareFilter(StringFilter):
  def __repr__(self):
    return '(entitlement-string-compare "%s")' % (self.s, )


class GenericStringFilter(StringFilter):
  def __repr__(self):
    return '(unknown-string "%s")' % (self.s, )

class IOKitPropertyFilter(StringFilter):
  def __repr__(self):
    return '(iokit-property "%s")' % (self.s, )

class IOKitPropertyRegexFilter(StringFilter):
  def __repr__(self):
    return '(iokit-property-regex #"%s")' % (self.s, )

class RightNameFilter(StringFilter):
  def __repr__(self):
    return '(right-name "%s")' % (self.s, )

class KextBundleIdFilter(StringFilter):
  def __repr__(self):
    return '(kext-bundle-id "%s")' % (self.s, )

class InfoTypeFilter(StringFilter):
  def __repr__(self):
    return '(info-type "%s")' % (self.s, )

class NotificationNameFilter(StringFilter):
  def __repr__(self):
    return '(notification-name "%s")' % (self.s, )

class DebugModeFilter(object):
  def __repr__(self):
    return '(debug-mode)'

class SysctlNameFilter(StringFilter):
  def __repr__(self):
    return '(sysctl-name "%s")' % (self.s, )

class ProcessNameFilter(StringFilter):
  def __repr__(self):
    return '(process-name "%s")' % (self.s, )

class RootlessBootDeviceFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(rootless-boot-device-filter)" 

class RootlessFileFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(rootless-file-filter)" 
	
class RootlessDiskFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(rootless-disk-filter)" 
	
class RootlessProcFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(rootless-proc-filter)" 
	

class PrivilegeIdFilter(object):
  def __init__(self, arg):
    if arg == 1000:
      self.arg = "PRIV_ADJTIME"
    elif arg == 1001:
      self.arg = "PRIV_PROC_UUID_POLICY"
    elif arg == 1002:
      self.arg = "PRIV_GLOBAL_PROC_INFO"
    elif arg == 1003:
      self.arg = "PRIV_SYSTEM_OVERRIDE"
    elif arg == 1004:
      self.arg = "PRIV_HW_DEBUG_DATA"
    elif arg == 1005:
      self.arg = "PRIV_SELECTIVE_FORCED_IDLE"
    elif arg == 1006:
      self.arg = "PRIV_PROC_TRACE_INSPECT"
    elif arg == 1008:
      self.arg = "PRIV_KERNEL_WORK_INTERNAL"
    elif arg == 6000:
      self.arg = "PRIV_VM_PRESSURE"
    elif arg == 6001:
      self.arg = "PRIV_VM_JETSAM"
    elif arg == 6002:
      self.arg = "PRIV_VM_FOOTPRINT_LIMIT"
    elif arg == 10000:
      self.arg = "PRIV_NET_PRIVILEGED_TRAFFIC_CLASS"
    elif arg == 10001:
      self.arg = "PRIV_NET_PRIVILEGED_SOCKET_DELEGATE"
    elif arg == 10002:
      self.arg = "PRIV_NET_INTERFACE_CONTROL"
    elif arg == 10003:
      self.arg = "PRIV_NET_PRIVILEGED_NETWORK_STATISTICS"
    elif arg == 10004:
      self.arg = "PRIV_NET_PRIVILEGED_NECP_POLICIES"
    elif arg == 10005:
      self.arg = "PRIV_NET_RESTRICTED_AWDL"
    elif arg == 10006:
      self.arg = "PRIV_NET_PRIVILEGED_NECP_MATCH"
    elif arg == 11000:
      self.arg = "PRIV_NETINET_RESERVEDPORT"
    elif arg == 14000:
      self.arg = "PRIV_VFS_OPEN_BY_ID"
    else:
      self.arg = "%u" % arg

  def __repr__(self):
    return "(privilege-id %s)" % self.arg
	
class ProcessAttributeFilter(object):
  def __init__(self, tgt):
    if tgt == 0:
      self.tgt = 'is-plugin'
    elif tgt == 1:
      self.tgt = 'is-installer'
    elif tgt == 2:
      self.tgt = 'is-restricted'
    elif tgt == 3:
      self.tgt = 'is-initproc'
    else:
      self.tgt = "unknown: %u" % tgt

  def __repr__(self):
    return '(process-attribute %s)' % (self.tgt, )
	  
class UidFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(uid %d)" % self.arg

class NvramVariableFilter(StringFilter):
  def __repr__(self):
    return '(nvram-variable "%s")' % (self.s, )

class NvramVariableRegexFilter(StringFilter):
  def __repr__(self):
    return '(nvram-variable-regex "%s")' % (self.s, )

class CsrFilter(object):
  def __init__(self, tgt):
    if tgt == 1:
      self.tgt = 'CSR_ALLOW_UNTRUSTED_KEXTS'
    elif tgt == 2:
      self.tgt = 'CSR_ALLOW_UNRESTRICTED_FS'
    elif tgt == 4:
      self.tgt = 'CSR_ALLOW_TASK_FOR_PID'
    elif tgt == 8:
      self.tgt = 'CSR_ALLOW_KERNEL_DEBUGGER'
    elif tgt == 16:
      self.tgt = 'CSR_ALLOW_APPLE_INTERNAL'
    elif tgt == 32:
      self.tgt = 'CSR_ALLOW_UNRESTRICTED_DTRACE'
    elif tgt == 64:
      self.tgt = 'CSR_ALLOW_UNRESTRICTED_NVRAM'
    elif tgt == 128:
      self.tgt = 'CSR_ALLOW_DEVICE_CONFIGURATION'
    else:
      self.tgt = "unknown: %u" % tgt

  def __repr__(self):
    return '(csr %s)' % (self.tgt, )
    
class HostSpecialPortFilter(object):
  def __init__(self, tgt):
    if tgt == 8:
      self.tgt = 'HOST_DYNAMIC_PAGER_PORT'
    elif tgt == 9:
      self.tgt = 'HOST_AUDIT_CONTROL_PORT'
    elif tgt == 10:
      self.tgt = 'HOST_USER_NOTIFICATION_PORT'
    elif tgt == 11:
      self.tgt = 'HOST_AUTOMOUNTD_PORT'
    elif tgt == 12:
      self.tgt = 'HOST_LOCKD_PORT'
    elif tgt == 13:
      self.tgt = 'unknown: 13'
    elif tgt == 14:
      self.tgt = 'HOST_SEATBELT_PORT'
    elif tgt == 15:
      self.tgt = 'HOST_KEXTD_PORT'
    elif tgt == 16:
      self.tgt = 'HOST_CHUD_PORT'
    elif tgt == 17:
      self.tgt = 'HOST_UNFREED_PORT'
    elif tgt == 18:
      self.tgt = 'HOST_AMFID_PORT'
    elif tgt == 19:
      self.tgt = 'HOST_GSSD_PORT'
    elif tgt == 20:
      self.tgt = 'HOST_TELEMETRY_PORT'
    elif tgt == 21:
      self.tgt = 'HOST_ATM_NOTIFICATION_PORT'
    elif tgt == 22:
      self.tgt = 'HOST_COALITION_PORT'
    elif tgt == 23:
      self.tgt = 'HOST_SYSDIAGNOSE_PORT'
    elif tgt == 24:
      self.tgt = 'HOST_XPC_EXCEPTION_PORT'
    elif tgt == 25:
      self.tgt = 'HOST_CONTAINERD_PORT'
    else:
      self.tgt = "unknown: %u" % tgt

  def __repr__(self):
    return '(host-special-port %s)' % (self.tgt, )	

class NotificationPayloadFilter(object):
  def __repr__(self):
    return '(notification-payload)'

class FileModeFilter(object):
  def __init__(self, mode):
    self.mode = mode

  def __repr__(self):
    return '(file-mode #o%04o)' % (self.mode, )

class GenericFilter(object):
  def __init__(self, typ, arg):
    self.typ = typ
    self.arg = arg

  def __repr__(self):
    return '(generic-fixme-filter 0x%2x 0x%04x)' % (self.typ, self.arg)

class IOCTLCommandFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(ioctl-command 0x%x)" % self.arg

class FSCTLCommandFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(fsctl-command 0x%x)" % self.arg

class XattrFilter(object):
  def __init__(self, attr):
    self.attr = attr

  def __repr__(self):
    return '(xattr %u)' % (self.attr, )

class DeviceMajorFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(device-major %u)" % self.arg

class DeviceMinorFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(device-minor %u)" % self.arg

class SocketTypeFilter(object):
  def __init__(self, arg):
    self.arg = arg
  def __repr__(self):
    return "(socket-type %u)" % self.arg

class EntitlementBooleanCompareFilter(object):
  def __init__(self, arg):
    if arg != 0:
        self.arg = "true"
    else:
        self.arg = "false"
  def __repr__(self):
    return "(entitlement-boolean-compare %s)" % self.arg

class SocketDomainFilter(object):
  def __init__(self, arg):
    if arg == 0:
      self.arg = "AF_UNSPEC"
    elif arg == 1:
      self.arg = "AF_UNIX"
    elif arg == 2:
      self.arg = "AF_INET"
    elif arg == 3:
      self.arg = "AF_IMPLINK"
    elif arg == 4:
      self.arg = "AF_PUP"
    elif arg == 5:
      self.arg = "AF_CHAOS"
    elif arg == 6:
      self.arg = "AF_NS"
    elif arg == 7:
      self.arg = "AF_ISO"
    elif arg == 8:
      self.arg = "AF_ECMA"
    elif arg == 9:
      self.arg = "AF_DATAKIT"
    elif arg == 10:
      self.arg = "AF_CCITT"
    elif arg == 11:
      self.arg = "AF_SNA"
    elif arg == 12:
      self.arg = "AF_DECnet"
    elif arg == 13:
      self.arg = "AF_DLI"
    elif arg == 14:
      self.arg = "AF_LAT"
    elif arg == 15:
      self.arg = "AF_HYLINK"
    elif arg == 16:
      self.arg = "AF_APPLETALK"
    elif arg == 17:
      self.arg = "AF_ROUTE"
    elif arg == 18:
      self.arg = "AF_LINK"
    elif arg == 19:
      self.arg = "AF_XTP"
    elif arg == 20:
      self.arg = "AF_COIP"
    elif arg == 21:
      self.arg = "AF_CNT"
    elif arg == 22:
      self.arg = "AF_RTIP"
    elif arg == 23:
      self.arg = "AF_IPX"
    elif arg == 24:
      self.arg = "AF_SIP"
    elif arg == 25:
      self.arg = "AF_PIP"
    elif arg == 26:
      self.arg = "AF_BLUE"
    elif arg == 27:
      self.arg = "AF_NDRV"
    elif arg == 28:
      self.arg = "AF_ISDN"
    elif arg == 29:
      self.arg = "AF_KEY"
    elif arg == 30:
      self.arg = "AF_INET6"
    elif arg == 31:
      self.arg = "AF_NATM"
    elif arg == 32:
      self.arg = "AF_SYSTEM"
    elif arg == 33:
      self.arg = "AF_NETBIOS"
    elif arg == 34:
      self.arg = "AF_PPP"
    elif arg == 35:
      self.arg = "AF_HDRCMPLT"
    elif arg == 36:
      self.arg = "AF_RESERVED"
    elif arg == 37:
      self.arg = "AF_IEEE80211"
    elif arg == 38:
      self.arg = "AF_UTUN"
    elif arg == 39:
      self.arg = "AF_MULTIPATH"
    else:
      self.arg = "%u" % arg
  def __repr__(self):
    return "(socket-domain %s)" % self.arg

class SocketProtocolFilter(object):
  def __init__(self, arg):
    if arg == 2:
        self.arg = "SYSPROTO_CONTROL"
    else:
        self.arg = "%u" % arg
  def __repr__(self):
    return "(socket-protocol %s)" % self.arg

class TargetFilter(object):
  def __init__(self, tgt):
    if tgt == 0:
      self.tgt = 'unknown - error ???'
    elif tgt == 1:
      self.tgt = 'self'
    elif tgt == 2:
      self.tgt = 'pgrp'
    elif tgt == 3:
      self.tgt = 'others'
    elif tgt == 4:
      self.tgt = 'children'
    elif tgt == 5:
      self.tgt = 'same-sandbox'
    else:
      self.tgt = "unknown: %u" % tgt

  def __repr__(self):
    return '(target %s)' % (self.tgt, )

class VnodeTypeFilter(object):
  def __init__(self, typ):
    if typ == 0:
      self.type = 'unknown - error ???'
    elif typ == 1:
      self.type = 'REGULAR-FILE'
    elif typ == 2:
      self.type = 'DIRECTORY'
    elif typ == 3:
      self.type = 'BLOCK-DEVICE'
    elif typ == 4:
      self.type = 'CHARACTER-DEVICE'
    elif typ == 5:
      self.type = 'SYMLINK'
    elif typ == 6:
      self.type = 'SOCKET'
    elif typ == 7:
      self.type = 'FIFO'
    elif typ == 65535:
      self.type = 'TTY'
    else:
      self.type = "unknown: %u" % typ

  def __repr__(self):
    return '(vnode-type %s)' % (self.type, )

class SemaphoreOwnerFilter(object):
  def __init__(self, sem):
    if sem == 0:
      self.sem = 'unknown - error ???'
    elif sem == 1:
      self.sem = 'self'
    elif sem == 2:
      self.sem = 'pgrp'
    elif sem == 3:
      self.sem = 'others'
    elif sem == 4:
      self.sem = 'children'
    elif sem == 5:
      self.sem = 'same-sandbox'
    elif sem == 6:
      self.sem = 'initproc'
    else:
      self.sem = "unknown: %u" % sem

  def __repr__(self):
    return '(semaphore-owner %s)' % (self.sem, )
    
def get_string_nopadding(f, arg):
  f.seek(arg * 8)
  count = struct.unpack('<I', f.read(4))[0]
  return f.read(count).strip("\x00")

def get_string(f, arg):
  f.seek(arg * 8)
  count = struct.unpack('<I', f.read(4))[0]
  f.read(1) # wtf?
  return f.read(count)

def get_network(f, arg):
  f.seek(arg * 8)
  typ, addr, port, arg1, arg2 = struct.unpack('<BBHHH', f.read(4 * 2))
  return (typ, addr, port)

def get_filter(f, re_table, filter, filter_arg): 
  if filter == 1:
    return LiteralFilter(get_string(f, filter_arg))
  elif filter == 0x81:
    return RegexFilter(re_table[filter_arg])
  elif filter == 0x82:
    return MountRelativeRegexFilter(re_table[filter_arg])
  elif filter == 2:
    return MountRelativeFilter(get_string(f, filter_arg))
  elif filter == 3:
    return XattrFilter(filter_arg)
  elif filter == 4:
    return FileModeFilter(filter_arg)
  elif filter == 5:
    return IPCPosixFilter(get_string(f, filter_arg))
  elif filter == 0x85:
    return IPCPosixRegexFilter(re_table[filter_arg])
  elif filter == 6:
    return GlobalNameFilter(get_string(f, filter_arg))
  elif filter == 0x86:
    return GlobalNameRegexFilter(re_table[filter_arg])
  elif filter == 7:
    return LocalNameFilter(get_string(f, filter_arg))
  elif filter == 0x87:
    return LocalNameRegexFilter(re_table[filter_arg])
  elif filter == 8:
    return LocalFilter(get_network(f, filter_arg))
  elif filter == 9:
    return RemoteFilter(get_network(f, filter_arg))
  elif filter == 10:
    return ControlFilter(get_string(f, filter_arg))
  elif filter == 11:
    return SocketDomainFilter(filter_arg)
  elif filter == 12:
    return SocketTypeFilter(filter_arg)

  elif filter == 13:
    return SocketProtocolFilter(filter_arg)

  elif filter == 14:
    return TargetFilter(filter_arg)
  elif filter == 15:
    return FSCTLCommandFilter(filter_arg)
  elif filter == 16:
    return IOCTLCommandFilter(filter_arg)
  elif filter == 17:
    return IOKitFilter(get_string(f, filter_arg))
  elif filter == 0x91:
    return IOKitRegexFilter(re_table[filter_arg])
  elif filter == 18:
    return IOKitPropertyFilter(get_string(f, filter_arg))
  elif filter == 0x92:
    return IOKitPropertyRegexFilter(re_table[filter_arg])
  elif filter == 19:
    return IOKitConnectionFilter(get_string(f, filter_arg))
  elif filter == 20:
    return DeviceMajorFilter(filter_arg)
  elif filter == 21:
    return DeviceMinorFilter(filter_arg)
  elif filter == 22:
    return DeviceConformsToFilter(get_string(f, filter_arg))
  elif filter == 23:
    return ExtensionFilter(get_string_nopadding(f, filter_arg))
  elif filter == 24:
    return ExtensionClassFilter(get_string(f, filter_arg))
  elif filter == 25:
    return AppleeventDestinationFilter(get_string(f, filter_arg))
  elif filter == 26:
    return DebugModeFilter()
  elif filter == 27:
    return RightNameFilter(get_string(f, filter_arg))
  elif filter == 28:
    return PreferenceDomainFilter(get_string(f, filter_arg))
  elif filter == 29:
    return VnodeTypeFilter(filter_arg)
  elif filter == 30:
    return RequireEntitlementFilter(get_string_nopadding(f, filter_arg))
  elif filter == 31:
    return EntitlementBooleanCompareFilter(get_string(f, filter_arg))
  elif filter == 32:
    return EntitlementStringCompareFilter(get_string(f, filter_arg))
  elif filter == 33:
    return KextBundleIdFilter(get_string(f, filter_arg))
  elif filter == 34:
    return InfoTypeFilter(get_string(f, filter_arg))
  elif filter == 35:
    return NotificationNameFilter(get_string(f, filter_arg))
  elif filter == 36:
    return NotificationPayloadFilter()
  elif filter == 37:
    return SemaphoreOwnerFilter(filter_arg)
  elif filter == 38:
    return SysctlNameFilter(get_string(f, filter_arg))
  elif filter == 39:
    return ProcessNameFilter(get_string(f, filter_arg))
  elif filter == 40:
    return RootlessBootDeviceFilter(filter_arg)
  elif filter == 41:
    return RootlessFileFilter(filter_arg)
  elif filter == 42:
    return RootlessDiskFilter(filter_arg)
  elif filter == 43:
    return RootlessProcFilter(filter_arg)
  elif filter == 44:
    return PrivilegeIdFilter(filter_arg)
  elif filter == 45:
    return ProcessAttributeFilter(filter_arg)
  elif filter == 46:
    return UidFilter(filter_arg)
  elif filter == 47:
    return NvramVariableFilter(get_string(f, filter_arg))
  elif filter == (47|128):
    return NvramVariableRegexFilter(re_table[filter_arg])
  elif filter == 48:
    return CsrFilter(filter_arg)
  elif filter == 49:
    return HostSpecialPortFilter(filter_arg)
  else:
    return GenericFilter(filter, filter_arg)
