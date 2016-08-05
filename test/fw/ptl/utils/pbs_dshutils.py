# coding: utf-8

# Copyright (C) 1994-2016 Altair Engineering, Inc.
# For more information, contact Altair at www.altair.com.
#
# This file is part of the PBS Professional ("PBS Pro") software.
#
# Open Source License Information:
#
# PBS Pro is free software. You can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Commercial License Information:
#
# The PBS Pro software is licensed under the terms of the GNU Affero General
# Public License agreement ("AGPL"), except where a separate commercial license
# agreement for PBS Pro version 14 or later has been executed in writing with
# Altair.
#
# Altair’s dual-license business model allows companies, individuals, and
# organizations to create proprietary derivative works of PBS Pro and
# distribute them - whether embedded or bundled with other software - under
# a commercial license agreement.
#
# Use of Altair’s trademarks, including but not limited to "PBS™",
# "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
# trademark licensing policies.
import platform
from subprocess import PIPE, Popen
import os
import sys
import re
import socket
import logging
import copy
import tempfile

LOG_DEBUG2 = logging.DEBUG - 1
LOG_INFOCLI = logging.INFO - 1
LOG_INFOCLI2 = logging.INFO - 2


class PtlUtilError(Exception):

    def __init__(self, message=None, rv=None, rc=None, msg=None):
        self.message = message
        self.rv = rv
        self.rc = rc
        self.msg = msg

    def __str__(self):
        return ('rc=' + str(self.rc) + ', rv=' + str(self.rv) +
                ',msg=' + str(self.msg))

    def __repr__(self):
        return (self.__class__.__name__ + '(rc=' + str(self.rc) + ', rv=' +
                str(self.rv) + ', msg=' + str(self.msg) + ')')


class Singleton(type):

    _clses = {}

    def __call__(cls, *args, **kwargs):
        key = (cls, args, str(kwargs))
        if key not in cls._clses:
            cls._clses[key] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._clses[key]


class PbsUser(object):

    __metaclass__ = Singleton

    def __init__(self, name, uid, gid, gecos, homedir, shell, sid=None):
        self.__dict__['pw_name'] = str(name)
        self.__dict__['pw_passwd'] = 'x'
        self.__dict__['pw_uid'] = int(uid)
        self.__dict__['pw_gid'] = int(gid)
        self.__dict__['pw_gecos'] = str(gecos)
        self.__dict__['pw_dir'] = str(homedir)
        self.__dict__['pw_shell'] = str(shell)
        self.__dict__['pw_sid'] = str(sid)
        self.__dict__['pw_groups'] = []
        self.__dict__['_fake'] = False
        self.__dict__['_record'] = (self.pw_name, self.pw_passwd,
                                    self.pw_uid, self.pw_gid,
                                    self.pw_gecos, self.pw_dir,
                                    self.pw_shell, self.pw_sid,
                                    map(lambda g: str(g), self.pw_groups))

    def __len__(self):
        return len(self.__dict__['_record'])

    def __getitem__(self, key):
        return self._record[key]

    def __setattr__(self, name, value):
        raise AttributeError('attribute read-only: %s' % name)

    def __repr__(self):
        return 'PbsUser' + str(self._record)

    def __str__(self):
        return self.__dict__['pw_name']

    def __int__(self):
        return self.__dict__['pw_uid']

    def __cmp__(self, other):
        this = str(self._record)
        if this == other:
            return 0
        elif this < other:
            return -1
        else:
            return 1

    def set_fake(self):
        self.__dict__['_fake'] = True

    def is_fake(self):
        return self.__dict__['_fake']


class PbsGroup(object):

    __metaclass__ = Singleton

    def __init__(self, name, gid, sid=None):
        self.__dict__['gr_name'] = str(name)
        self.__dict__['gr_passwd'] = 'x'
        self.__dict__['gr_gid'] = int(gid)
        self.__dict__['gr_mem'] = []
        self.__dict__['gr_sid'] = str(sid)
        self.__dict__['_fake'] = False
        self.__dict__['_record'] = (self.gr_name, self.gr_passwd,
                                    self.gr_gid,
                                    map(lambda u: str(u), self.gr_mem),
                                    self.gr_sid)

    def __len__(self):
        return len(self.__dict__['_record'])

    def __getitem__(self, key):
        return self._record[key]

    def __setattr__(self, name, value):
        raise AttributeError('attribute read-only: %s' % name)

    def __repr__(self):
        return 'PbsGroup' + str(self._record)

    def __str__(self):
        return self.__dict__['gr_name']

    def __int__(self):
        return self.__dict__['gr_gid']

    def __cmp__(self, other):
        this = str(self._record)
        if this == other:
            return 0
        elif this < other:
            return -1
        else:
            return 1

    def set_fake(self):
        self.__dict__['_fake'] = True

    def is_fake(self):
        return self.__dict__['_fake']


class DshUtils(object):

    """
    PBS shell utilities

    A set of tools to run commands, copy files, get process information and
    parse a PBS configuration on an arbitrary host
    """

    logger = logging.getLogger(__name__)
    _h2p = {}  # host to platform cache
    _h2c = {}  # host to pbs_conf file cache
    _h2l = {}  # host to islocal cache
    _h2which = {}  # host to which cache

    def __init__(self):
        self._current_user = None
        logging.addLevelName('INFOCLI', LOG_INFOCLI)
        setattr(self.logger, 'infocli',
                lambda *args: self.logger.log(LOG_INFOCLI, *args))
        logging.addLevelName('DEBUG2', LOG_DEBUG2)
        setattr(self.logger, 'debug2',
                lambda *args: self.logger.log(LOG_DEBUG2, *args))
        logging.addLevelName('INFOCLI2', LOG_INFOCLI2)
        setattr(self.logger, 'infocli2',
                lambda *args: self.logger.log(LOG_INFOCLI2, *args))
        self.mom_conf_map = {'PBS_MOM_SERVICE_PORT': '-M',
                             'PBS_MANAGER_SERVICE_PORT': '-R',
                             'PBS_HOME': '-d',
                             'PBS_BATCH_SERVICE_PORT': '-S',
                             }
        self.server_conf_map = {'PBS_MOM_SERVICE_PORT': '-M',
                                'PBS_MANAGER_SERVICE_PORT': '-R',
                                'PBS_HOME': '-d',
                                'PBS_BATCH_SERVICE_PORT': '-p',
                                'PBS_SCHEDULER_SERVICE_PORT': '-S',
                                }
        self.sched_conf_map = {'PBS_HOME': '-d',
                               'PBS_BATCH_SERVICE_PORT': '-p',
                               'PBS_SCHEDULER_SERVICE_PORT': '-S',
                               }
        self._tempdir = {}
        self.platform = sys.platform
        self.is_linux = self.platform.startswith('linux')
        self.is_windows = self.platform.startswith('win32')
        self.is_64bit = platform.architecture()[0] == '64bit'

    def get_platform(self, hostname=None, pyexec=None):
        """
        Get a local or remote platform info, essentially the value of
        Python's sys.platform

        hostname - The hostname to query for platform info

        pyexec - A path to a Python interpreter to use to query a remote host
        for platform info

        For efficiency the value is cached and retrieved from the cache upon
        subsequent request
        """
        if hostname is None:
            return sys.platform
        if hostname in self._h2p:
            return self._h2p[hostname]
        if self.is_localhost(hostname):
            self._h2p[hostname] = sys.platform
            return sys.platform
        if pyexec is None:
            pyexec = self.which(hostname, 'python')
        cmd = [pyexec, '-c', '"import sys; print sys.platform"']
        ret = self.run_cmd(hostname, cmd=cmd)
        if ret['rc'] != 0 or len(ret['out']) == 0:
            _msg = 'Unable to retrieve platform info, '
            _msg += 'defaulting to local platform'
            self.logger.warning(_msg)
            platform = sys.platform
        else:
            platform = ret['out'][0].strip()
        self._h2p[hostname] = platform
        return platform

    def _parse_file(self, hostname, path):
        """
         helper function to parse a file containing entries of the form
         <key>=<value> into a Python dictionary format
        """
        if hostname is None:
            hostname = socket.gethostname()
        try:
            rv = self.cat(hostname, path, level=LOG_DEBUG2,
                          logerr=False)
            if rv['rc'] != 0:
                return {}
            props = {}
            for l in rv['out']:
                if l.find('=') != -1 and l[0] != '#':
                    c = l.split('=')
                    props[c[0]] = c[1].strip()
        except:
            raise PtlUtilError(rc=1, rv=False,
                               msg='error parsing file ' + str(path))
        return props

    def _set_file(self, hostname, fin, fout, append, pairs):
        """
        Create a file out of a set of dictionaries, possibly parsed from an
        input file. @see _parse_file.

        hostname - the name of the host on which to operate. Defaults to
        localhost

        fin - the input file to read from

        fout - the output file to write to

        append - If true, append to the output file.

        vars - The key/value pairs to write to fout
        """
        if hostname is None:
            hostname = socket.gethostname()
        if append:
            conf = self._parse_file(hostname, fin)
        else:
            conf = {}
        conf = dict(conf.items() + pairs.items())
        try:
            (fd, fn) = self.mkstemp()
            self.chmod(hostname, fn, 0644)
            for k, v in conf.items():
                os.write(fd, str(k) + '=' + str(v) + os.linesep)
            os.close(fd)
            self.chown(path=fn, uid=0, gid=0, sudo=True)
            self.run_copy(hostname, fn, fout, sudo=True)
            self.rm(path=fn, sudo=True)
        except:
            raise PtlUtilError(rc=1, rv=False,
                               msg='error writing to file ' + str(fout))
        return conf

    def get_pbs_conf_file(self, hostname=None):
        """
        Get the path of the pbs conf file. Defaults back to /etc/pbs.conf
        if unsuccessful
        """
        if self.is_windows:
            if self.is_64bit:
                dflt_conf = 'C:\\Program Files (x86)\\'
            else:
                dflt_conf = 'C:\\Program Files\\'
            dflt_conf += 'PBS Pro\\pbs.conf'
        else:
            dflt_conf = '/etc/pbs.conf'
        if hostname is None:
            hostname = socket.gethostname()
        if hostname in self._h2c:
            return self._h2c[hostname]
        if self.is_localhost(hostname):
            dflt_conf = os.environ.get('PBS_CONF_FILE', dflt_conf)
        else:
            pc = ('"import os;print [False, os.environ[\'PBS_CONF_FILE\']]'
                  '[\'PBS_CONF_FILE\' in os.environ]"')
            cmd = [self.which(hostname, 'python'), '-c', pc]
            ret = self.run_cmd(hostname, cmd, logerr=False)
            if ((ret['rc'] != 0) and (len(ret['out']) > 0) and
                    (ret['out'][0] != 'False')):
                dflt_conf = ret['out'][0]
        self._h2c[hostname] = dflt_conf
        return dflt_conf

    def parse_pbs_config(self, hostname=None, path=None):
        " initialize pbs_conf dictionary by parsing pbs config file "
        if path is None:
            path = self.get_pbs_conf_file(hostname)
        return self._parse_file(hostname, path)

    def set_pbs_config(self, hostname=None, fin=None, fout=None,
                       append=True, confs={}):
        """
        Set environment/configuration variables in a pbs.conf file

        hostname - the name of the host on which to operate

        fin - the input pbs.conf file

        fout - the name of the output pbs.conf file, defaults to /etc/pbs.conf

        append - whether to append to fout or not, defaults to True

        confs - The key/value pairs to create
        """
        if fin is None:
            fin = self.get_pbs_conf_file(hostname)
        if fout is None and fin is not None:
            fout = fin
        if confs:
            self.logger.info('Set ' + str(confs) + ' in ' + fout)
        return self._set_file(hostname, fin, fout, append, confs)

    def unset_pbs_config(self, hostname=None, fin=None, fout=None,
                         confs=[]):
        """
        Unset environment/configuration variables in a pbs.conf file

        hostname - the name of the host on which to operate

        fin - the input pbs.conf file

        fout - the name of the output pbs.conf file, defaults to /etc/pbs.conf

        confs - The configuration keys to unset
        """
        if fin is None:
            fin = self.get_pbs_conf_file(hostname)
        if fout is None and fin is not None:
            fout = fin
        if isinstance(confs, str):
            confs = confs.split(',')
        elif isinstance(confs, dict):
            confs = confs.keys()
        cur_confs = self.parse_pbs_config(hostname, fin)
        for k in confs:
            if k in cur_confs:
                del cur_confs[k]
        self.logger.info('Unset ' + ",".join(confs) + ' from ' + fout)
        return self._set_file(hostname, fin, fout, append=False,
                              pairs=cur_confs)

    # TODO: move this to lib
    def get_pbs_server_name(self, pbs_conf=None):
        """
        Return the name of the server which may be different than PBS_SERVER,
        in order, this method looks at PBS_PRIMARY, PBS_SERVER_HOST_NAME, and
        PBS_LEAF_NAME, and PBS_SERVER
        """
        if pbs_conf is None:
            pbs_conf = self.parse_pbs_config()
        if 'PBS_PRIMARY' in pbs_conf:
            return pbs_conf['PBS_PRIMARY']
        elif 'PBS_SERVER_HOST_NAME' in pbs_conf:
            return pbs_conf['PBS_SERVER_HOST_NAME']
        elif 'PBS_LEAF_NAME' in pbs_conf:
            return pbs_conf['PBS_LEAF_NAME']
        return pbs_conf['PBS_SERVER']

    def parse_pbs_environment(self, hostname=None, path=None):
        """
        Initialize pbs_conf dictionary by parsing pbs config file
        """
        if path is None:
            if self.is_windows:
                if self.is_64bit:
                    path = 'C:\\Program Files (x86)\\'
                else:
                    path = 'C:\\Program Files\\'
                path += 'PBS Pro\\home\\pbs_environment'
            else:
                path = '/var/spool/pbs/pbs_environment'
        return self._parse_file(hostname, path)

    def set_pbs_environment(self, hostname=None, fin=None, fout=None,
                            append=True, pairs={}):
        if fin is None:
            if self.is_windows:
                if self.is_64bit:
                    fin = 'C:\\Program Files (x86)\\'
                else:
                    fin = 'C:\\Program Files\\'
                fin += 'PBS Pro\\home\\pbs_environment'
            else:
                fin = '/var/spool/pbs/pbs_environment'
        if fout is None and fin is not None:
            fout = fin
        return self._set_file(hostname, fin, fout, append, pairs)

    def parse_rhosts(self, hostname=None, user=None):
        if hostname is None:
            hostname = socket.gethostname()
        if user is None:
            user = self.getuid()
        try:
            # Assumes identical file system layout on every host
            if isinstance(user, int):
                home = self.getpwuid(user).pw_dir
            else:
                home = self.getpwnam(user).pw_dir
            rhost = os.path.join(home, '.rhosts')
            rv = self.cat(hostname, rhost, level=LOG_DEBUG2, runas=user,
                          logerr=False)
            if rv['rc'] != 0:
                return {}
            props = {}
            for l in rv['out']:
                if l[0] != '#':
                    if l.strip() == '':
                        continue
                    k, v = l.split()
                    v = v.strip()
                    if k in props:
                        if isinstance(props[k], list):
                            props[k].append(v)
                        else:
                            props[k] = [props[k], v]
                    else:
                        props[k] = v
        except:
            raise PtlUtilError(rc=1, rv=False,
                               msg='error parsing .rhost')
        return props

    def set_rhosts(self, hostname=None, user=None, entry={}, append=True):
        if hostname is None:
            hostname = socket.gethostname()
        if user is None:
            user = self.getuid()
        if append:
            conf = self.parse_rhosts(hostname, user)
            for k, v in entry.items():
                if k in conf:
                    if isinstance(conf[k], list):
                        if isinstance(v, list):
                            conf[k].extend(v)
                        else:
                            conf[k].append(v)
                    else:
                        if isinstance(v, list):
                            conf[k] = [conf[k]] + v
                        else:
                            conf[k] = [conf[k], v]
                else:
                    conf[k] = v
        else:
            conf = entry
        try:
            # currently assumes identical file system layout on every host
            if isinstance(user, int):
                _user = self.getpwuid(user)
                home = _user.pw_dir
                uid = _user.pw_uid
            else:
                # user might be PbsUser object
                _user = self.getpwnam(str(user))
                home = _user.pw_dir
                uid = _user.pw_uid
            rhost = os.path.join(home, '.rhosts')
            (fd, fn) = self.mkstemp(hostname, mode=0755)
            for k, v in conf.items():
                if isinstance(v, list):
                    for eachprop in v:
                        os.write(fd, "%s %s%s" % (str(k), str(eachprop),
                                                  os.linesep))
                else:
                    os.write(fd, "%s %s%s" % (str(k), str(v), os.linesep))
            os.write(fd, os.linesep)
            os.close(fd)
            ret = self.run_copy(hostname, src=fn, dest=rhost, runas=_user,
                                logerr=False)
            self.rm(hostname, path=fn)
            self.chmod(hostname, path=rhost, mode=0600, runas=_user,
                       logerr=False)
            self.chown(hostname, path=rhost, uid=_user, gid=_user.pw_groups[0],
                       logerr=False)
            if ret['rc'] != 0:
                raise Exception(ret['out'] + ret['err'])
        except Exception, e:
            raise PtlUtilError(rc=1, rv=False,
                               msg='error writing .rhosts ' + str(e))
        return conf

    # TODO: move this to lib
    def map_pbs_conf_to_cmd(self, cmd_map={}, pconf={}):
        cmd = []
        for k, v in pconf.items():
            if k in cmd_map:
                cmd += [cmd_map[k], str(v)]
        return cmd

    def get_current_user(self):
        """
        helper function to return the name of the current user
        """
        if self._current_user is not None:
            return self._current_user
        self._current_user = self.getpwuid(self.getuid())[0]
        return self._current_user

    def check_group_membership(self, username=None, uid=None, grpname=None,
                               gid=None):
        """
        Checks whether a user, passed in as username or uid, is a member of a
        group, passed in as group name or group id.

        username - The username to inquire about

        uid - The uid of the user to inquire about (alternative to username)

        grpname - The groupname to check for user membership

        gid - The group id to check for user membership (alternative to
        grpname)
        """
        if username is None and uid is None:
            self.logger.warning('A username or uid was expected')
            return True
        if grpname is None and gid is None:
            self.logger.warning('A grpname or gid was expected')
            return True
        if grpname:
            try:
                _g = self.getgrnam(grpname)
                smems = [str(x) for x in _g.gr_mem]
                imems = [int(x) for x in _g.gr_mem]
                if username is not None and username in smems:
                    return True
                elif uid is not None and uid in imems:
                    return True
            except:
                self.logger.error('Unknown group')
        return False

    def group_memberships(self, group_list):
        """
        Returns all group memberships as a dictionary of group names and
        associated memberships
        """
        groups = {}
        if len(group_list) == 0:
            return groups
        users_list = [u.pw_name for u in self.getpwall()]
        glist = {}
        for u in users_list:
            info = self.get_id_info(u)
            if not info['pgroup'] in glist.keys():
                glist[info['pgroup']] = [info['name']]
            else:
                glist[info['pgroup']].append(info['name'])
            for g in info['groups']:
                if g not in glist.keys():
                    glist[g] = []
                if not info['name'] in glist[g]:
                    glist[g].append(info['name'])
        for g in group_list:
            if g in glist.keys():
                groups[g] = glist[g]
            else:
                try:
                    i = self.getgrnam(g)
                    groups[g] = i.gr_mem
                except KeyError:
                    pass
        return groups

    def get_id_info(self, user):
        """
        Return user info in dic format

        user - The username to inquire about

        Returned dic format:
        {
            "uid": <uid of given user>,
            "gid": <gid of given user's primary group>,
            "name": <name of given user>,
            "pgroup": <name of primary group of given user>,
            "groups": <list of names of groups of given user>
        }
        """
        info = {'uid': None, 'gid': None, 'name': None, 'pgroup': None,
                'groups': None}
        if self.is_linux:
            ret = self.run_cmd(cmd=['id', '-a', str(user)], logerr=False)
        elif self.is_windows:
            ret = self.run_cmd(cmd=['Get-UserInfo', '-All', '-Name', str(user)],
                               logerr=False)
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
        if ret['rc'] == 0:
            p = re.compile(r'(?P<uid>\d+)\((?P<name>[\w\s."\\\'-]+)\)')
            map_list = re.findall(p, ret['out'][0].strip())
            info['uid'] = int(map_list[0][0])
            info['name'] = map_list[0][1].strip()
            info['gid'] = int(map_list[1][0])
            info['pgroup'] = map_list[1][1].strip()
            groups = []
            if len(map_list) > 2:
                for g in map_list[2:]:
                    groups.append(g[1].strip().strip('"').strip("'"))
            info['groups'] = groups
        return info

    def get_tempdir(self, hostname=None):
        """
        Return the temporary directory on the given host
        Default host is localhost.
        """
        if hostname is None:
            hostname = socket.gethostname()
        if hostname in self._tempdir:
            return self._tempdir[hostname]
        if self.is_localhost(hostname):
            self._tempdir[hostname] = tempfile.gettempdir()
        else:
            cmd = [self.which(hostname, 'python'), '-c',
                   '"import tempfile;print tempfile.gettempdir()"']
            ret = self.run_cmd(hostname, cmd, level=logging.DEBUG)
            if ret['rc'] == 0:
                self._tempdir[hostname] = ret['out'][0].strip()
            else:
                # Optimistically fall back to tempfile.gettempdir() on localhost
                self._tempdir[hostname] = tempfile.gettempdir()
        return self._tempdir[hostname]

    def __run_cmd_windows(self, hosts=None, cmd=None, sudo=False, stdin=None,
                          stdout=PIPE, stderr=PIPE, input=None, cwd=None,
                          env=None, runas=None, logerr=True, as_script=False,
                          wait_on_script=True, level=LOG_INFOCLI2):
        if hosts is None:
            hosts = socket.gethostname()
        if isinstance(hosts, str):
            hosts = hosts.split(',')
        if not isinstance(hosts, list):
            err_msg = 'target hostnames must be a comma-separated '
            err_msg += 'string or list'
            raise PtlUtilError(rc=1, rv=False, msg=err_msg)
        if isinstance(cmd, (list, tuple)):
            cmd = " ".join(cmd)
        psm_path = os.path.dirname(os.path.abspath(os.path.abspath(__file__)))
        psm_path = os.path.join(psm_path, 'psm')
        ps_script = ['$env:PSModulePath += ";%s"' % psm_path]
        ps_script += ['Import-Module ptl']

    def __run_cmd_linux(self, hosts=None, cmd=None, sudo=False, stdin=None,
                        stdout=PIPE, stderr=PIPE, input=None, cwd=None,
                        env=None, runas=None, logerr=True, as_script=False,
                        wait_on_script=True, level=LOG_INFOCLI2):
        """
        Run a command on a host or list of hosts.

        hosts - the name of hosts on which to run the command, can be a comma-
        separated string or a list. Defaults to localhost

        cmd - the command to run

        sudo - whether to run the command as root or not. Defaults to False.

        stdin - custom stdin. Defaults to PIPE

        stdout - custom stdout. Defaults to PIPE

        stderr - custom stderr. Defaults to PIPE

        input - input to pass to the pipe on target host, e.g. PBS answer file

        cwd - working directory on local host from which command is run

        env - environment variables to set on local host

        runas - run command as given user. Defaults to calling user

        logerr - whether to log error messages or not. Defaults to True

        as_script - if True, run the command in a script created as a
        temporary file that gets deleted after being run. This is used mainly
        to circumvent some implementations of sudo that prevent passing
        environment variables through sudo.

        wait_on_script - If True (default) waits on process launched as script
        to return.

        Returns error, output, and return code as a dictionary
        {'out':...,'err':...,'rc':...} if hosts has only one hostname
        {'hostname': {'out':...,'err':...,'rc':...},
         ...
        } if hosts has more that one hostname
        """

        rshcmd = []
        sudocmd = []
        if level is None:
            level = self.logger.level
        _user = self.get_current_user()
        # runas may be a PbsUser object, ensure it is a string for the
        # remaining of the function
        if runas is not None:
            if isinstance(runas, int):
                runas = self.getpwuid(runas).pw_name
            elif not isinstance(runas, str):
                # must be as PbsUser object
                runas = str(runas)
        if isinstance(cmd, str):
            cmd = cmd.split()
        if hosts is None:
            hosts = socket.gethostname()
        if isinstance(hosts, str):
            hosts = hosts.split(',')
        if not isinstance(hosts, list):
            err_msg = 'target hostnames must be a comma-separated '
            err_msg += 'string or list'
            raise PtlUtilError(rc=1, rv=False, msg=err_msg)
        ret = {}
        for targethost in hosts:
            islocal = self.is_localhost(targethost)
            if not islocal:
                rshcmd = ['ssh'] + [targethost]
            if sudo or ((runas is not None) and (runas != _user)):
                sudocmd = ['sudo', '-H']
                if runas is not None:
                    sudocmd += ['-u', runas]
            # Initialize information to return
            reth = {'out': None, 'err': None, 'rc': None}
            if as_script:
                _fd, _script = self.mkstemp()
                f = open(_script, 'w')
                script_body = ['#!/bin/bash']
                if cwd is not None:
                    script_body += ['cd "%s"' % cwd]
                    cwd = None
                if isinstance(cmd, str):
                    script_body += [cmd]
                elif isinstance(cmd, list):
                    script_body += [" ".join(cmd)]
                f.write(os.linesep.join(script_body))
                os.close(_fd)
                f.close()
                os.chmod(_script, 0755)
                if not islocal:
                    self.run_copy(targethost, _script, _script)
                    os.remove(_script)
                runcmd = rshcmd + sudocmd + [_script]
            else:
                runcmd = rshcmd + sudocmd + cmd
            _msg = targethost.split('.')[0] + ': '
            _runcmd = map(lambda x: '\'\'' if x == '' else str(x), runcmd)
            _msg += ' '.join(_runcmd)
            _msg = [_msg]
            if as_script:
                _msg += ['Contents of ' + _script + ':']
                _msg += ['-' * 40, os.linesep.join(script_body), '-' * 40]
            self.logger.log(level, os.linesep.join(_msg))
            if input:
                self.logger.log(level, input)
            try:
                p = Popen(runcmd, bufsize=-1, stdin=stdin, stdout=stdout,
                          stderr=stderr, cwd=cwd, env=env)
            except Exception, e:
                _msg = "Error running command " + str(runcmd)
                if as_script:
                    _msg += os.linesep + 'Script contents: ' + os.linesep
                    _msg += os.linesep.join(script_body)
                _msg += os.linesep + str(e)
                raise PtlUtilError(rc=1, rv=False, msg=_msg)
            if as_script and not wait_on_script:
                o = p.stdout.readline()
                e = p.stderr.readline()
                reth['rc'] = 0
            else:
                (o, e) = p.communicate(input)
                reth['rc'] = p.returncode
            if as_script:
                # must pass as_script=False otherwise it will loop infinite
                self.rm(targethost, path=_script, as_script=False)
            # handle the case where stdout is not a PIPE
            if o is not None:
                reth['out'] = o.splitlines()
            else:
                reth['out'] = []
            # Some output can be very verbose, for example listing many lines
            # of a log file, those messages are typically channeled through
            # at level DEBUG2, since we don't to pollute the output with too
            # verbose an information, we log at most at level DEBUG
            if level < logging.DEBUG:
                self.logger.log(level, 'out: ' + str(reth['out']))
            else:
                self.logger.debug('out: ' + str(reth['out']))
            if e is not None:
                reth['err'] = e.splitlines()
            else:
                reth['err'] = []
            if reth['err'] and logerr:
                self.logger.error('err: ' + str(reth['err']))
            else:
                self.logger.debug('err: ' + str(reth['err']))
            self.logger.debug('rc: ' + str(reth['rc']))
            if len(hosts) > 1:
                ret[targethost] = copy.deepcopy(reth)
            else:
                ret = reth
        return ret

    def run_cmd(self, hosts=None, cmd=None, sudo=False, stdin=None,
                stdout=PIPE, stderr=PIPE, input=None, cwd=None,
                env=None, runas=None, logerr=True, as_script=False,
                wait_on_script=True, level=LOG_INFOCLI2):
        if self.is_linux:
            return self.__run_cmd_linux(hosts=hosts, cmd=cmd, sudo=sudo,
                                        stdin=stdin, stdout=stdout,
                                        stderr=stderr, input=input, cwd=cwd,
                                        env=env, runas=runas, logerr=logerr,
                                        as_script=as_script,
                                        wait_on_script=wait_on_script,
                                        level=level)
        elif self.is_windows:
            return self.__run_cmd_windows(hosts=hosts, cmd=cmd, sudo=sudo,
                                          stdin=stdin, stdout=stdout,
                                          stderr=stderr, input=input, cwd=cwd,
                                          env=env, runas=runas, logerr=logerr,
                                          as_script=as_script,
                                          wait_on_script=wait_on_script,
                                          level=level)
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
    def run_copy(self, hosts=None, src=None, dest=None, sudo=False, uid=None,
                 gid=None, mode=None, env=None, logerr=True,
                 recursive=False, runas=None, level=LOG_INFOCLI2):
        """
        copy a file or directory to specified target hosts.

        hosts - the host(s) to which to copy the data. Can be a comma-
        separated string or a list

        src - the path to the file or directory to copy. If src is remote,
        it must be prefixed by the hostname. e.g. remote1:/path,remote2:/path

        dest - the destination path.

        sudo - whether to copy as root or not. Defaults to False

        uid - optionally change ownership of dest to the specified user id,
        referenced by uid number or username

        gid - optionally change ownership of dest to the specified
        group name/id

        mode - optinoally set mode bits of dest

        env - environment variables to set on the calling host

        logerr - whether to log error messages or not. Defaults to True.

        recursive - whether to copy a directory (when true) or a file.
        Defaults to False.

        runas - run command as user

        level - logging level, defaults to DEBUG

        returns {'out':<outdata>, 'err': <errdata>, 'rc':<retcode>} upon
        and None if no source file specified
        """
        if src is None:
            raise PtlUtilError(rc=1, rv=False, msg='no source file specified')
        if hosts is None:
            hosts = socket.gethostname()
        if isinstance(hosts, str):
            hosts = hosts.split(',')
        if not isinstance(hosts, list):
            raise PtlUtilError(rc=1, rv=False,
                               msg='destination must be a string or a list')
        if dest is None:
            dest = src
        for targethost in hosts:
            islocal = self.is_localhost(targethost)
            if sudo and not islocal:
                # to avoid a file copy as root, we copy it as current user
                # and move it remotely to the desired path/name.
                # First, get a remote temporary filename
                cmd = [self.which(targethost, 'python'), '-c',
                       '"import tempfile;print ' +
                       'tempfile.mkstemp(\'PtlPbstmpcopy\')[1]"']
                # save original destination
                sudo_save_dest = dest
                # Make the target of the copy the temporary file
                dest = self.run_cmd(targethost, cmd, level=level,
                                    logerr=logerr)['out'][0]
                cmd = []
            else:
                # if not using sudo or target is local, initialize the
                # command to run accordingly
                sudo_save_dest = None
                if sudo:
                    cmd = [self.which(targethost, 'sudo'), '-H']
                else:
                    cmd = []
            # Remote copy if target host is remote or if source file/dir is
            # remote.
            if (not islocal) or (':' in src):
                copy_cmd = [self.which(targethost, 'scp'), '-p']
                cmd += copy_cmd
                if recursive:
                    cmd += ['-r']
                cmd += [src]
                if islocal:
                    cmd += [dest]
                else:
                    cmd += [targethost + ':' + dest]
            else:
                cmd += [self.which(targethost, 'cp'), '-p']
                if recursive:
                    cmd += ['-r']
                cmd += [src]
                cmd = cmd + [dest]
            ret = self.run_cmd(socket.gethostname(), cmd, env=env, runas=runas,
                               logerr=logerr, level=level)
            if ret['rc'] != 0:
                raise PtlUtilError(rc=ret['rc'], rv=False, msg=str(ret['err']))
            elif sudo_save_dest:
                cmd = [self.which(targethost, 'mv')]
                cmd += [dest, sudo_save_dest]
                ret = self.run_cmd(targethost, cmd=cmd, sudo=True, level=level)
                dest = sudo_save_dest
                if ret['rc'] != 0:
                    raise PtlUtilError(rc=ret['rc'], rv=False,
                                       msg=str(ret['err']))
            if mode is not None:
                self.chmod(targethost, path=dest, mode=mode, sudo=sudo,
                           runas=runas)
            if ((uid is not None and uid != self.get_current_user()) or
                    gid is not None):
                self.chown(targethost, path=dest, uid=uid, gid=gid, sudo=True,
                           recursive=False)
            return ret

    def run_ptl_cmd(self, hostname, cmd, sudo=False, stdin=None, stdout=PIPE,
                    stderr=PIPE, input=None, cwd=None, env=None, runas=None,
                    logerr=True, as_script=False, wait_on_script=True,
                    level=LOG_INFOCLI2):
        """
        Wrapper method of run_cmd to run PTL command
        """
        # Add absolute path of command also add log level to command
        self.logger.infocli('running command "%s" on %s' % (' '.join(cmd),
                                                            hostname))
        _cmd = [self.which(hostname, exe=cmd[0])]
        _cmd += ['-l', logging.getLevelName(self.logger.parent.level)]
        _cmd += cmd[1:]
        cmd = _cmd
        self.logger.debug(' '.join(cmd))
        dest = None
        if ('PYTHONPATH' in os.environ.keys() and
                not self.is_localhost(hostname)):
            # TODO: change this
            body = ['#!/bin/bash']
            body += ['PYTHONPATH=%s exec %s' % (os.environ['PYTHONPATH'],
                                                ' '.join(cmd))]
            fd, fn = self.mkstemp(mode=0777)
            os.write(fd, os.linesep.join(body))
            os.close(fd)
            tmpdir = self.get_tempdir(hostname)
            dest = os.path.join(tmpdir, os.path.basename(fn))
            self.run_copy(hostname, fn, dest, mode=0777)
            self.rm(None, path=fn, sudo=True, force=True, logerr=False)
            cmd = dest
        ret = self.run_cmd(hostname, cmd, sudo, stdin, stdout, stderr, input,
                           cwd, env, runas, logerr, as_script, wait_on_script,
                           level)
        if dest is not None:
            self.rm(hostname, path=dest, sudo=True, force=True, logerr=False)
        # TODO: check why output is coming to ret['err']
        if ret['rc'] == 0:
            ret['out'] = ret['err']
            ret['err'] = []
        return ret

    def is_localhost(self, host=None):
        """
        returns true if specified host (by name) is the localhost
        all aliases matching the hostname are searched
        """
        if host is None:
            return True
        if host in self._h2l:
            return self._h2l[host]
        try:
            (hostname, aliaslist, iplist) = socket.gethostbyname_ex(host)
        except:
            raise PtlUtilError(rc=1, rv=False,
                               msg='error getting host by name: ' + host)
        localhost = socket.gethostname()
        if localhost == hostname or localhost in aliaslist:
            self._h2l[host] = True
        try:
            ipaddr = socket.gethostbyname(localhost)
        except:
            self.logger.error('could not resolve local host name')
            return False
        if ipaddr in iplist:
            self._h2l[host] = True
            return True
        self._h2l[host] = False
        return False

    def isdir(self, hostname=None, path=None, sudo=False, runas=None,
              level=LOG_INFOCLI2):
        """
        Returns True if directory pointed to by path exists and False otherwise

        hostname - The name of the host on which to check for directory

        path - The path to the directory to check

        sudo - Whether to run the command as a privileged user

        runas - run command as user

        level - Logging level
        """
        if path is None:
            return False
        if self.is_localhost(hostname) and (not sudo) and (runas is None):
            return os.path.isdir(path)
        else:
            if self.is_linux:
                dirname = os.path.dirname(path)
                basename = os.path.basename(path)
                cmd = ['ls', '-l', dirname]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                                   logerr=False, level=level)
                if ret['rc'] != 0:
                    return False
                else:
                    for l in ret['out']:
                        if basename == l[-len(basename):] and l.startswith('d'):
                            return True
                return False
            elif self.is_windows:
                cmd = ['Test-Path', '-PathType', 'Container', '-Path', path]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                                   logerr=False, level=level)
                if ret['rc'] == 0:
                    return eval(ret['out'][0].strip())
                return False
            else:
                raise PtlUtilError(rc=1, rv=False,
                                   msg='Unsupported platform detected!')

    def isfile(self, hostname=None, path=None, sudo=False, runas=None,
               level=LOG_INFOCLI2):
        """
        Returns True if file pointed to by path exists, and False otherwise

        hostname - The name of the host on which to check for file

        path - The path to the file to check

        sudo - Whether to run the command as a privileged user

        runas - run command as user

        level - Logging level
        """

        if path is None:
            return False
        if self.is_localhost(hostname) and (not sudo) and (runas is None):
            return os.path.isfile(path)
        else:
            if self.is_linux:
                cmd = ['ls', '-l', path]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                                   logerr=False, level=level)
                if ret['rc'] != 0:
                    return False
                elif ret['out']:
                    if not ret['out'][0].startswith('d'):
                        return True
                return False
            elif self.is_windows:
                cmd = ['Test-Path', '-PathType', 'Leaf', '-Path', path]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                                   logerr=False, level=level)
                if ret['rc'] == 0:
                    return eval(ret['out'][0].strip())
                return False
            else:
                raise PtlUtilError(rc=1, rv=False,
                                   msg='Unsupported platform detected!')

    def getmtime(self, hostname=None, path=None, sudo=False, runas=None,
                 level=LOG_INFOCLI2):
        """
        Returns Modified time of given file

        hostname - The name of the host on which file exists

        path - The path to the file to get mtime

        sudo - Whether to run the command as a privileged user

        runas - run command as user

        level - Logging level
        """

        if path is None:
            return None
        if self.is_localhost(hostname) and (not sudo) and (runas is None):
            return os.path.getmtime(path)
        else:
            py_cmd = '"import os; print os.path.getmtime(\'%s\')"' % path
            cmd = [self.which(hostname, 'python'), '-c', py_cmd]
            ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                               logerr=False, level=level)
            if ((ret['rc'] == 0) and (len(ret['out']) == 1) and
                    (isinstance(eval(ret['out'][0].strip()), (int, float)))):
                return eval(ret['out'][0].strip())
        return None

    def listdir(self, hostname=None, path=None, sudo=False, runas=None,
                level=LOG_INFOCLI2):
        """
        Return a list containing the names of the entries in the directory

        hostname - The name of the host on which to list for directory
        path - The path to directory to list

        sudo - Whether to chmod as root or not. Defaults to False

        runas - run command as user

        level - Logging level.
        """

        if path is None:
            return None
        if self.is_localhost(hostname) and (not sudo) and (runas is None):
            files = os.listdir(path)
            return map(lambda p: os.path.join(path, p.strip()), files)
        else:
            if self.is_linux:
                ret = self.run_cmd(hostname, cmd=['ls', path], sudo=sudo,
                                   runas=runas, logerr=False, level=level)
                if ret['rc'] == 0:
                    files = ret['out']
                else:
                    return None
                return map(lambda p: os.path.join(path, p.strip()), files)
            elif self.is_windows:
                cmd = ['Get-Dir', '-Path', path]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                                   logerr=False, level=level)
                if ret['rc'] == 0:
                    files = ret['out']
                else:
                    return None
                return map(lambda p: p.strip(), files)
            else:
                raise PtlUtilError(rc=1, rv=False,
                                   msg='Unsupported platform detected!')

    def chmod(self, hostname=None, path=None, mode=None, sudo=False,
              runas=None, recursive=False, logerr=True,
              level=logging.INFOCLI2):
        """
        Generic function of chmod with remote host support

        hostname - hostname (default current host)

        path - the path to the file or directory to chmod

        mode - mode to apply as octal number like 0777, 0666 etc.

        sudo - whether to chmod as root or not. Defaults to False

        runas - run command as user

        recursive - whether to chmod a directory (when true) or a file.
        Defaults to False.

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.

        level - logging level, defaults to INFOCLI2

        Return - True on success otherwise False
        """
        if (path is None) or (mode is None):
            return False
        if self.is_linux:
            cmd = [self.which(hostname, 'chmod')]
            if recursive:
                cmd += ['-R']
            cmd += [oct(mode)]
            if isinstance(path, (list, tuple)):
                cmd += path
            else:
                cmd += [path]
        elif self.is_windows:
            cmd = ['Set-FileMode', '-Mode', oct(mode), '-Path']
            if isinstance(path, (list, tuple)):
                cmd += [','.join(map(lambda x: '"' + x + '"', path))]
            else:
                cmd += [path]
            if recursive:
                cmd += ['-Recurse']
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                           runas=runas, cwd=cwd, level=level)
        if ret['rc'] == 0:
            return True
        return False

    def chown(self, hostname=None, path=None, uid=None, gid=None, sudo=False,
              recursive=False, runas=None, cwd=None, logerr=True,
              level=LOG_INFOCLI2):
        """
        Generic function of chown with remote host support

        hostname - hostname (default current host)

        path - the path to the file or directory to chown

        uid - uid to apply (must be either user name or uid or -1)

        gid - gid to apply (must be either group name or gid or -1)

        sudo - whether to chown as root or not. Defaults to False

        recursive - whether to chmod a directory (when true) or a file.
        Defaults to False.

        runas - run command as user

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.

        level - logging level, defaults to INFOCLI2

        Return - True on success otherwise False
        """
        if path is None or (uid is None and gid is None):
            return False
        _u = ''
        if isinstance(uid, int) and uid != -1:
            _u = self.getpwuid(uid).pw_name
        elif isinstance(uid, str) and (uid != '-1'):
            _u = uid
        else:
            # must be as PbsUser object
            if str(uid) != '-1':
                _u = str(uid)
        if _u == '':
            return False
        if self.is_linux:
            cmd = [self.which(hostname, 'chown')]
            if recursive:
                cmd += ['-R']
            cmd += [_u]
            if isinstance(path, (list, tuple)):
                cmd += path
            else:
                cmd += [path]
        elif self.is_windows:
            cmd = ['Set-FileOwner', '-Owner', _u, '-Path']
            if isinstance(path, (list, tuple)):
                cmd += [','.join(map(lambda x: '"' + x + '"', path))]
            else:
                cmd += [path]
            if recursive:
                cmd += ['-Recurse']
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                           runas=runas, cwd=cwd, level=level)
        if ret['rc'] == 0:
            if gid is not None:
                rv = self.chgrp(hostname, path, gid=gid, sudo=sudo,
                                level=level, recursive=recursive, cwd=cwd,
                                runas=runas, logerr=logerr)
                if not rv:
                    return False
            return True
        return False

    def chgrp(self, hostname=None, path=None, gid=None, sudo=False,
              recursive=False, runas=None, cwd=None, logerr=True,
              level=LOG_INFOCLI2):
        """
        Generic function of chgrp with remote host support

        hostname - hostname (default current host)

        path - the path to the file or directory to chown

        gid - gid to apply (must be either group name or gid or -1)

        sudo - whether to chgrp as root or not. Defaults to False

        recursive - whether to chmod a directory (when true) or a file.
        Defaults to False.

        runas - run command as user

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.

        level - logging level, defaults to INFOCLI2

        Return - True on success otherwise False
        """
        if path is None or gid is None:
            return False
        _g = ''
        if isinstance(gid, int) and gid != -1:
            _g = self.getgrgid(gid).gr_name
        elif isinstance(gid, str) and (gid != '-1'):
            _g = gid
        else:
            # must be as PbsGroup object
            if str(gid) != '-1':
                _g = str(gid)
        if _g == '':
            return False
        if self.is_linux:
            cmd = [self.which(hostname, 'chgrp')]
            if recursive:
                cmd += ['-R']
            cmd += [_g]
            if isinstance(path, (list, tuple)):
                cmd += path
            else:
                cmd += [path]
        elif self.is_windows:
            cmd = ['Set-FileGroup', '-Group', _g, '-Path']
            if isinstance(path, (list, tuple)):
                cmd += [','.join(map(lambda x: '"' + x + '"', path))]
            else:
                cmd += [path]
            if recursive:
                cmd += ['-Recurse']
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                           runas=runas, cwd=cwd, level=level)
        if ret['rc'] == 0:
            return True
        return False

    def which(self, hostname=None, exe=None, level=LOG_INFOCLI2):
        """
        Generic function of which with remote host support

        hostname - hostname (default current host)

        exe - executable to locate (can be full path also)
        (if exe is full path then only basename will be used to locate)

        level - logging level, defaults to INFOCLI2
        """
        if exe is None:
            return None
        if hostname is None:
            hostname = socket.gethostname()
        oexe = exe
        exe = os.path.basename(exe)
        if hostname in self._h2which.keys():
            if exe in self._h2which[hostname]:
                return self._h2which[hostname][exe]
        if self.is_linux:
            sudo_wrappers_dir = '/opt/tools/wrappers'
            _exe = os.path.join(sudo_wrappers_dir, exe)
            if os.path.isfile(_exe) and os.access(_exe, os.X_OK):
                if hostname not in self._h2which.keys():
                    self._h2which.setdefault(hostname, {exe: _exe})
                else:
                    self._h2which[hostname].setdefault(exe, _exe)
                return _exe
            cmd = ['which']
        elif self.is_windows:
            cmd = ['Find-Command', '-Path']
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
        cmd += [exe]
        ret = self.run_cmd(hostname, cmd=cmd, logerr=False,
                           level=level)
        if (ret['rc'] == 0) and (len(ret['out']) == 1):
            path = ret['out'][0].strip()
            if hostname not in self._h2which.keys():
                self._h2which.setdefault(hostname, {exe: path})
            else:
                self._h2which[hostname].setdefault(exe, path)
            return path
        else:
            return oexe

    def rm(self, hostname=None, path=None, sudo=False, runas=None,
           recursive=False, force=False, cwd=None, logerr=True,
           as_script=False, level=LOG_INFOCLI2):
        """
        Generic function of rm with remote host support

        hostname - hostname (default current host)

        path - the path to the files or directories to remove
        for more than one files or directories pass as list

        sudo - whether to remove files or directories as root or not.
        Defaults to False

        runas - remove files or directories as given user.
        Defaults to calling user

        recursive - remove files or directories and their contents recursively

        force - force remove files or directories

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.

        as_script - if True, run the rm in a script created as a
        temporary file that gets deleted after being run. This is used mainly
        to handle wildcard in path list. Defaults to False.

        level - logging level, defaults to INFOCLI2

        Return - True on success otherwise False
        """
        if (path is None) or (len(path) == 0):
            return True
        if self.is_linux:
            cmd = [self.which(hostname, 'rm')]
            if recursive and force:
                cmd += ['-rf']
            else:
                if recursive:
                    cmd += ['-r']
                if force:
                    cmd += ['-f']
            if isinstance(path, list):
                for p in path:
                    if p == '/':
                        msg = 'encountered a dangerous package path ' + p
                        raise PtlUtilError(rc=1, rv=False, msg=msg)
                cmd += path
            else:
                if path == '/':
                    msg = 'encountered a dangerous package path ' + path
                    raise PtlUtilError(rc=1, rv=False, msg=msg)
                cmd += [path]
            ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                               runas=runas, cwd=cwd, level=level,
                               as_script=as_script)
            if ret['rc'] != 0:
                return False
            return True
        elif self.is_windows:
            if isinstance(path, list):
                for p in path:
                    if p == 'C:\\':
                        msg = 'encountered a dangerous package path ' + p
                        raise PtlUtilError(rc=1, rv=False, msg=msg)
            else:
                if path == 'C:\\':
                    msg = 'encountered a dangerous package path ' + path
                    raise PtlUtilError(rc=1, rv=False, msg=msg)
            _cmd = ['Remove-Item', '-Confirm:$false']
            if recursive:
                _cmd += ['-Recurse']
            if force:
                _cmd += ['-Force']
            if isinstance(path, list):
                for p in path:
                    cmd = _cmd + [p]
                    ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo,
                                       logerr=logerr,
                                       runas=runas, cwd=cwd, level=level,
                                       as_script=as_script)
                    if ret['rc'] != 0:
                        return False
                return True
            else:
                cmd = _cmd + [path]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                                   runas=runas, cwd=cwd, level=level,
                                   as_script=as_script)
                if ret['rc'] != 0:
                    return False
                return True
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def mkdir(self, hostname=None, path=None, mode=None, sudo=False,
              runas=None, parents=True, cwd=None, logerr=True,
              as_script=False, level=LOG_INFOCLI2):
        """
        Generic function of mkdir with remote host support

        hostname - hostname (default current host)

        path - the path to the directories to create
        for more than one directories pass as list

        mode - mode to use while creating directories
        (must be octal like 0777)

        sudo - whether to create directories as root or not. Defaults to False

        runas - create directories as given user. Defaults to calling user

        parents - create parent directories as needed. Defaults to True

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.

        as_script - if True, run the command in a script created as a
        temporary file that gets deleted after being run. This is used mainly
        to handle wildcard in path list. Defaults to False.

        level - logging level, defaults to INFOCLI2

        Return - True on success otherwise False
        """
        if (path is None) or (len(path) == 0):
            return True
        if self.is_linux:
            cmd = [self.which(hostname, 'mkdir')]
            if parents:
                cmd += ['-p']
            if mode is not None:
                cmd += ['-m', oct(mode)]
            if isinstance(path, list):
                cmd += path
            else:
                cmd += [path]
            ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                               runas=runas, cwd=cwd, level=level,
                               as_script=as_script)
            if ret['rc'] != 0:
                return False
            return True
        elif self.is_windows:
            _cmd = ['New-Item', '-ItemType', 'Directory', '-Force']
            _cmd += ['-Confirm:$false']
            if isinstance(path, list):
                for p in path:
                    cmd = _cmd + [p]
                    ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo,
                                       logerr=logerr,
                                       runas=runas, cwd=cwd, level=level,
                                       as_script=as_script)
                    if ret['rc'] != 0:
                        return False
                    if mode is not None:
                        rc = self.chmod(hostname, path=p, mode=oct(mode),
                                        sudo=sudo, recursive=parents,
                                        runas=runas, cwd=cwd, logerr=logerr,
                                        level=level)
                        if not rc:
                            return False
                return True
            else:
                cmd = _cmd + [path]
                ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, logerr=logerr,
                                   runas=runas, cwd=cwd, level=level,
                                   as_script=as_script)
                if ret['rc'] != 0:
                    return False
                if mode is not None:
                    rc = self.chmod(hostname, path=p, mode=oct(mode),
                                    sudo=sudo, recursive=parents,
                                    runas=runas, cwd=cwd, logerr=logerr,
                                    level=level)
                    if not rc:
                        return False
                return True
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def cat(self, hostname=None, filename=None, sudo=False, runas=None,
            cwd=None, logerr=True, level=LOG_INFOCLI2):
        """
        Generic function of cat with remote host support

        hostname - hostname (default current host)

        filename - the path to the filename to cat

        sudo - whether to create directories as root or not. Defaults to False

        runas - create directories as given user. Defaults to calling user

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.

        Return - output of run_cmd
        """
        if self.is_linux:
            cmd = [self.which(hostname, 'cat'), filename]
        elif self.is_windows:
            cmd = ['Get-Content', '"%s"' % filename]
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')
        return self.run_cmd(hostname, cmd=cmd, sudo=sudo, cwd=cwd,
                            runas=runas, logerr=logerr, level=level)

    def cmp(self, hostname=None, fileA=None, fileB=None, sudo=False,
            runas=None, cwd=None, logerr=True):
        """
        Compare two files and return 0 if they are identical or non-zero if
        not

        hostname - the name of the host to operate on

        fileA - the first file to compare

        fileB - the file to compare fileA to

        sudo - run the command as a privileged user

        runas - run the cmp command as given user

        cwd - working directory on local host from which command is run

        logerr - whether to log error messages or not. Defaults to True.
        """

        if fileA is None and fileB is None:
            return 0
        if fileA is None or fileB is None:
            return 1
        cmd = ['cmp', fileA, fileB]
        ret = self.run_cmd(hostname, cmd=cmd, sudo=sudo, runas=runas,
                           cwd=cwd, logerr=logerr)
        return ret['rc']

    def useradd(self, name, uid=None, gid=None, shell='/bin/bash',
                create_home_dir=True, home_dir=None, groups=None, logerr=True,
                level=LOG_INFOCLI2):
        self.logger.info('adding user ' + str(name))
        cmd = ['useradd']
        if uid is not None:
            cmd += ['-u', str(uid)]
        if shell is not None:
            cmd += ['-s', shell]
        if gid is not None:
            cmd += ['-g', str(gid)]
        if create_home_dir:
            cmd += ['-m']
        if home_dir is not None:
            cmd += ['-d', home_dir]
        if (groups is not None) and (len(groups) > 0):
            cmd += ['-G', ','.join(map(lambda g: str(g), groups))]
        cmd += [str(name)]
        ret = self.run_cmd(cmd=cmd, logerr=logerr, sudo=True, level=level)
        if (ret['rc'] != 0) and logerr:
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def userdel(self, name, del_home=True, force=True, logerr=True,
                level=LOG_INFOCLI2):
        try:
            uinfo = self.getpwnam(str(name))
        except:
            if logerr:
                self.logger.error("User %s does not exist!" % (str(name)))
            return
        cmd = ['userdel']
        if del_home:
            cmd += ['-r']
        if force:
            cmd += ['-f']
        cmd += [str(name)]
        self.logger.info('deleting user ' + str(name))
        ret = self.run_cmd(cmd=cmd, sudo=True, logerr=False, level=level)
        if (ret['rc'] != 0) and logerr:
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def groupadd(self, name, gid=None, logerr=True, level=LOG_INFOCLI2):
        self.logger.info('adding group ' + str(name))
        cmd = ['groupadd']
        if gid is not None:
            cmd += ['-g', str(gid)]
        cmd += [str(name)]
        ret = self.run_cmd(cmd=cmd, sudo=True, logerr=False, level=level)
        if (ret['rc'] != 0) and logerr:
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def groupdel(self, name, logerr=True, level=LOG_INFOCLI2):
        self.logger.info('deleting group ' + str(name))
        cmd = ['groupdel', str(name)]
        ret = self.run_cmd(cmd=cmd, sudo=True, logerr=logerr, level=level)
        if (ret['rc'] != 0) and logerr:
            raise PtlUtilError(rc=ret['rc'], rv=False, msg=ret['err'])

    def mkstemp(self, hostname=None, suffix='', prefix='PtlPbs', dir=None,
                text=False, uid=None, gid=None, mode=None, body=None,
                level=LOG_INFOCLI2):
        """
        Create a temp file by calling tempfile.mkstemp

        hostname - the hostname on which to query tempdir from

        suffix - the file name will end with this suffix

        prefix - the file name will begin with this prefix

        dir - the file will be created in this directory

        text - the file is opened in text mode is this is true else in binary
        mode

        uid - Optional username or uid of temp file owner

        gid - Optional group name or gid of temp file group owner

        mode - Optional mode bits to assign to the temporary file

        body - Optional content to write to the temporary file

        level - logging level, defaults to INFOCLI2
        """
        if not self.is_localhost(hostname):
            tmp_args = []
            if suffix:
                tmp_args += ['suffix=\'' + suffix + '\'']
            if prefix:
                tmp_args += ['prefix=\'' + prefix + '\'']
            if dir is not None:
                tmp_args += ['dir=\'' + str(dir) + '\'']
            if text:
                tmp_args += ['text=\'' + str(text) + '\'']
            args = ",".join(tmp_args)
            ret = self.run_cmd(hostname,
                               [self.which(hostname, 'python'), '-c',
                                '"import tempfile; print tempfile.mkstemp('
                                + args + ')"'],
                               level=level)
            if ret['rc'] == 0 and ret['out']:
                (fd, fn) = eval(ret['out'][0])
        else:
            (fd, fn) = tempfile.mkstemp(suffix, prefix, dir, text)
        if body is not None:
            if isinstance(body, list):
                os.write(fd, os.linesep.join(body))
            else:
                os.write(fd, body)
        if mode is not None:
            self.chmod(hostname, fn, mode=mode,
                       level=LOG_INFOCLI2, sudo=True)
        if (uid is not None) or (gid is not None):
            self.chown(hostname, fn, uid=uid, gid=gid, sudo=True)
        return fd, fn

    def mkdtemp(self, hostname=None, suffix='', prefix='PtlPbs', dir=None,
                uid=None, gid=None, mode=None, level=LOG_INFOCLI2):
        """
        Create a temp dir by calling tempfile.mkdtemp

        hostname - the hostname on which to query tempdir from

        suffix - the directory name will end with this suffix

        prefix - the directory name will begin with this prefix

        dir - the directory will be created in this directory

        uid - Optional username or uid of temp directory owner

        gid - Optional group name or gid of temp directory group owner

        mode - Optional mode bits to assign to the temporary directory

        level - logging level, defaults to INFOCLI2
        """
        if not self.is_localhost(hostname):
            tmp_args = []
            if suffix:
                tmp_args += ['suffix=\'' + suffix + '\'']
            if prefix:
                tmp_args += ['prefix=\'' + prefix + '\'']
            if dir is not None:
                tmp_args += ['dir=\'' + str(dir) + '\'']
            args = ",".join(tmp_args)
            ret = self.run_cmd(hostname,
                               [self.which(hostname, 'python'), '-c',
                                '"import tempfile; print tempfile.mkdtemp('
                                + args + ')"'],
                               level=level)
            if ret['rc'] == 0 and ret['out']:
                fn = ret['out'][0]
        else:
            fn = tempfile.mkdtemp(suffix, prefix, dir)
        if mode is not None:
            self.chmod(hostname, fn, mode=mode, recursive=True,
                       level=LOG_INFOCLI2, sudo=True)
        if (uid is not None) or (gid is not None):
            self.chown(hostname, fn, uid=uid, gid=gid, recursive=True,
                       sudo=True)
        return fn

    @staticmethod
    def __parse_ps_ug(lines):
        _ret = {}
        for l in lines:
            l = l.strip()
            if len(l) == 0:
                continue
            if '=' in l:
                k, v = l.split('=')
                _ret[k.strip()] = v.strip()
            else:
                _ret[l] = {}
        return _ret

    def getuid(self):
        if self.is_linux:
            return os.getuid()
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-CurrentUserId'])
            if ret['rc'] != 0:
                msg = 'Failed to get uid!'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            else:
                return int(ret['out'][0].strip())
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgid(self):
        if self.is_linux:
            return os.getgid()
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-CurrentGroupId'])
            if ret['rc'] != 0:
                msg = 'Failed to get gid!'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            else:
                return int(ret['out'][0].strip())
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getpwall(self):
        if self.is_linux:
            import pwd
            _users = pwd.getpwall()
            users = []
            for user in _users:
                _user = PbsUser(name=user.pw_name, uid=user.pw_uid,
                                gid=user.pw_gid, gecos=user.pw_gecos,
                                homedir=user.pw_dir, shell=user.pw_shell,
                                sid=None)
                users.append(_user)
            return users
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-AllUser'])
            if ret['rc'] != 0:
                msg = 'Failed to get users!'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _users = self.__parse_ps_ug(ret['out'])
            users = []
            for v in _users.values():
                uid = v['sid'].split('-')[-1]
                _user = PbsUser(name=v['name'], uid=uid, gid=v['gid'],
                                gecos=v['gecos'], homedir=v['dir'],
                                # TODO: find shell
                                shell=None, sid=v['sid'])
                users.append(_user)
            return users
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getpwnam(self, name):
        name = str(name)
        if self.is_linux:
            import pwd
            user = pwd.getpwnam(name)
            return PbsUser(name=user.pw_name, uid=user.pw_uid,
                           gid=user.pw_gid, gecos=user.pw_gecos,
                           homedir=user.pw_dir, shell=user.pw_shell,
                           sid=None)
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-UserByName', '-Name', name])
            if ret['rc'] != 0:
                msg = 'Failed to get user'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _user = self.__parse_ps_ug(ret['out']).values()[0]
            uid = _user['sid'].split('-')[-1]
            return PbsUser(name=_user['name'], uid=uid, gid=_user['gid'],
                           gecos=_user['gecos'], homedir=_user['dir'],
                           # TODO: find shell
                           shell=None, sid=_user['sid'])
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getpwuid(self, uid):
        uid = int(uid)
        if self.is_linux:
            import pwd
            user = pwd.getpwuid(uid)
            return PbsUser(name=user.pw_name, uid=user.pw_uid,
                           gid=user.pw_gid, gecos=user.pw_gecos,
                           homedir=user.pw_dir, shell=user.pw_shell,
                           sid=None)
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-UserById', '-Id', str(uid)])
            if ret['rc'] != 0:
                msg = 'Failed to get user'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _user = self.__parse_ps_ug(ret['out']).values()[0]
            uid = _user['sid'].split('-')[-1]
            return PbsUser(name=_user['name'], uid=uid, gid=_user['gid'],
                           gecos=_user['gecos'], homedir=_user['dir'],
                           # TODO: find shell
                           shell=None, sid=_user['sid'])
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgrall(self):
        if self.is_linux:
            import grp
            _groups = grp.getgrall()
            groups = []
            for group in _groups:
                _group = PbsGroup(name=group.gr_name, gid=group.gr_gid,
                                  sid=None)
                for mem in group.gr_mem:
                    _mem = self.getpwnam(mem)
                    _mem.pw_groups.append(_group)
                    _group.gr_mem.append(_mem)
                groups.append(_group)
            return groups
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-AllGroup'])
            if ret['rc'] != 0:
                msg = 'Failed to get groups'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _groups = self.__parse_ps_ug(ret['out'])
            groups = []
            for v in _groups.values():
                gid = v['sid'].split('-')[-1]
                _group = PbsGroup(name=v['name'], gid=gid, sid=v['sid'])
                members = v['mem']
                if members == '__NONE__':
                    members = []
                else:
                    members = members.split(',')
                for mem in members:
                    _mem = self.getpwnam(mem)
                    _mem.pw_groups.append(_group)
                    _group.gr_mem.append(_mem)
                groups.append(_group)
            return groups
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgrgid(self, gid):
        gid = int(gid)
        if self.is_linux:
            import grp
            _group = grp.getgrgid(gid)
            group = PbsGroup(name=_group.gr_name, gid=_group.gr_gid,
                             sid=None)
            for mem in _group.gr_mem:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-GroupById', '-Id', str(gid)])
            if ret['rc'] != 0:
                msg = 'Failed to get group'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _group = self.__parse_ps_ug(ret['out']).values()[0]
            gid = _group['sid'].split('-')[-1]
            group = PbsGroup(name=_group['name'], gid=gid, sid=_group['sid'])
            members = _group['mem']
            if members == '__NONE__':
                members = []
            else:
                members = members.split(',')
            for mem in members:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def getgrnam(self, name):
        name = str(name)
        if self.is_linux:
            import grp
            _group = grp.getgrnam(name)
            group = PbsGroup(name=_group.gr_name, gid=_group.gr_gid,
                             sid=None)
            for mem in _group.gr_mem:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        elif self.is_windows:
            ret = self.run_cmd(None, cmd=['Get-GroupByName', '-Name', name])
            if ret['rc'] != 0:
                msg = 'Failed to get group'
                raise PtlUtilError(rc=1, rv=False, msg=msg)
            _group = self.__parse_ps_ug(ret['out']).values()[0]
            gid = _group['sid'].split('-')[-1]
            group = PbsGroup(name=_group['name'], gid=gid, sid=_group['sid'])
            members = _group['mem']
            if members == '__NONE__':
                members = []
            else:
                members = members.split(',')
            for mem in members:
                _mem = self.getpwnam(mem)
                _mem.pw_groups.append(group)
                group.gr_mem.append(_mem)
            return group
        else:
            raise PtlUtilError(rc=1, rv=False,
                               msg='Unsupported platform detected!')

    def is_privilege_user(self):
        if self.is_linux:
            return self.getuid() == 0
        elif self.is_windows:
            # TODO: Implement below?
            return True
