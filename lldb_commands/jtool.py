

import lldb
import os
import re
import shlex
import optparse
import subprocess

ds_jtool_dict = {}
base_address = None


def makeSureEverythingIsOK(result, prog):
    global ds_jtool_dict

    ds_jtool_path = ds_jtool_dict.get(prog)
    if not ds_jtool_path:
        # I'd expect jtool to be in /usr/local/bin/
        if "/usr/local/bin" not in os.environ["PATH"]:
            os.environ["PATH"] += os.pathsep + "/usr/local/bin/"
        if subprocess.call(["/usr/bin/which", prog], shell=False) != 0:
            result.SetError("Can't find {prog} in PATH or {prog} isn't installed "
                            "(http://www.newosxbook.com/tools/jtool.html), "
                            "you can determine this in LLDB via \""
                            "(lldb) script import os; os.environ['PATH']\"\n"
                            "You can persist this via "
                            "(lldb) script os.environ['PATH'] += os.pathsep + /path/to/{prog}/folder".
                            format(prog=prog))
            return 1

        ds_jtool_path = subprocess.Popen(['/usr/bin/which', prog],
                                         shell=False,
                                         stdout=subprocess.PIPE).communicate()[0].rstrip(b'\n\r').decode()
        ds_jtool_dict[prog] = ds_jtool_path.replace('//', '/')
        return 0
    else:
        return 0


def get_cputype_string(target, addr):
    global base_address
    header_addr = addr.GetModule().GetObjectFileHeaderAddress().GetLoadAddress(target)

    base_address = header_addr
    # magic at +0, cputype at +4
    cputype_addr = header_addr + 4
    int32_t_ptr_type = target.GetBasicType(lldb.eBasicTypeInt)

    cpu_val = target.CreateValueFromAddress("__unused", target.ResolveLoadAddress(cputype_addr), int32_t_ptr_type)
    cputype = cpu_val.unsigned
    if cputype == 0x01000007:
        return "x86_64"
    elif cputype == 7:
        return "i386"
    elif cputype == 12:
        return "armv7"
    elif cputype == 0x0100000c:
        return "arm64"
    else:
        print("Unknown cputype: {}", format(cputype))
        return None


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f jtool.jtool jtool -h "wrapper for @Morpheus______\'s jtool"')
    debugger.HandleCommand('command script add -f jtool.jtool2 jtool2 -h "wrapper for @Morpheus______\'s jtool2"')


def jtool(debugger, command, exe_ctx, result, internal_dict):
    """
    Documentation for how to use jtool goes here
    """
    handle_command(command, exe_ctx, result, 'jtool')


def jtool2(debugger, command, exe_ctx, result, internal_dict):
    """
    Documentation for how to use jtool2 goes here
    """
    handle_command(command, exe_ctx, result, 'jtool2')


def handle_command(command, exe_ctx, result, prog):
    if makeSureEverythingIsOK(result, prog):
        return

    target = exe_ctx.GetTarget()
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser(prog)
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return

    opts = generateOptionArgsFromOptions(options, prog)
    executablePath = None
    module = None
    addr = None
    # No args default to main executable
    if len(args) == 0:
        executablePath = target.GetExecutable().fullpath
        module = target.module[target.GetExecutable().fullpath]
        if len(opts) > 0:
            result.AppendMessage("Inspecting main executable, {}{}{}".format("" if isXcode() else "\033[36m", module.GetFileSpec().basename, "" if isXcode() else "\033[0m"))

    if len(args) >= 1:
        module = target.module[args[0]]
        if module is None:
            # Did they pass in a hex/int value?
            try:
                address = int(args[0])
            except:

                #  Hex didn't work, just try an int
                try:
                    address = int(args[0], 16)
                except:
                    result.SetError("Unable to find module \"{}\", use \"image list -f ModuleName\"".format(args[0]))
                    return 

            addr = target.ResolveLoadAddress(address)
            if module is None:
                module = addr.GetModule()
                result.AppendMessage("\"{}\" found in {}{}{}".format(args[0], "" if isXcode() else "\033[36m", module.GetFileSpec().basename, "" if isXcode() else "\033[0m"))

            if addr.module.IsValid() == False:
                result.SetError("Unable to find module for address {}".format(hex(address)))
                return

        if module is not None:
            executablePath = module.GetFileSpec().fullpath

    if addr is None:
        addr = module.GetObjectFileHeaderAddress()

    cputype_str = get_cputype_string(target, addr)
    if cputype_str is None:
        result.SetError("Unable to parse cputype, tell Derek about this")
        return

    proc_args = []
    if not isXcode():
        proc_args.append("JCOLOR=1")

    global ds_jtool_dict
    ds_jtool_path = ds_jtool_dict[prog]
    proc_args.append(ds_jtool_path)
    if len(opts) > 0:
        if prog == 'jtool':
            proc_args.append("-arch")
            proc_args.append(cputype_str)
        proc_args.extend(opts)
        proc_args.append("\"{}\"".format(executablePath))

    if options.debug:
        # print (proc_args)
        print(" ".join(proc_args))

    cmd = None
    if len(proc_args) > 1:
        cmd = ' '.join(proc_args)
    else:
        cmd = proc_args[0]

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = p.communicate()
    code = p.wait()

    result.AppendMessage(output.decode())
    if len(error) > 0:
        result.SetError(error.decode())


def generateOptionArgsFromOptions(options, prog):
    retOpts = []
    if options.opt_h:
        retOpts.append("-h")

    if prog == 'jtool2':
        if options.opt_help:
            retOpts.append("--help")

    if options.opt_e:
        retOpts.append("--ent")

    if options.opt_f:
        retOpts.append("-f")

    if options.opt_l:
        retOpts.append("-l")

    if options.opt_L:
        retOpts.append("-L")

    if options.opt_pages:
        retOpts.append("--pages")

    if options.opt_S:
        retOpts.append("-S")

    if options.opt_s:
        retOpts.append("--sig")

    # if options.opt_bind:
    #     retOpts.append("-bind")

    return retOpts


def generate_option_parser(prog):
    usage = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage, prog=prog)
    # parser.add_option("-m", 
    #                   action="store_true",
    #                   default=None,
    #                   dest="module",
    #                   help="This is a placeholder option to show you how to use options with strings")
    parser.add_option("", "--h",
                      action="store_true",
                      default=False,
                      dest="opt_h",
                      help="print header (ELF or Mach-O)")

    if prog == 'jtool2':
        parser.add_option("", "--H",
                          action="store_true",
                          default=False,
                          dest="opt_help",
                          help="print jtool2 help info")

    parser.add_option("-e", "--ent",
                      action="store_true",
                      default=False,
                      dest="opt_e",
                      help="print entitlements")
    parser.add_option("-f", "--opt_f", 
                      action="store_true",
                      default=False,
                      dest="opt_f",
                      help="print fat header")
    parser.add_option("-l", "--opt_l",
                      action="store_true",
                      default=False,
                      dest="opt_l",
                      help="List sections/commands in binary")
    parser.add_option("-L", "--opt_L", 
                      action="store_true",
                      default=False,
                      dest="opt_L",
                      help="List shared libraries used (like LDD)")
    parser.add_option("-S", "--opt_S", 
                      action="store_true",
                      default=False,
                      dest="opt_S",
                      help="List Symbols (like NM)")
    parser.add_option("-s", "--sig",
                      action="store_true",
                      default=False,
                      dest="opt_s",
                      help="print signature")

    parser.add_option("", "--pages",
                      action="store_true",
                      default=False,
                      dest="opt_pages",
                      help="Show file page map (similar to pagestuff(1))")

    # *********************************************************************
    # dyldinfo Compatible Options:
    # *********************************************************************
    # parser.add_option("", "--bind", 
    #                   action="store_true",
    #                   default=False,
    #                   dest="opt_bind",
    #                   help="print addresses dyld will set based on symbolic lookups")

    parser.add_option("-G", "--debug", 
                      action="store_true",
                      default=False,
                      dest="debug",
                      help="Used for debugging the generated jtool script")
    return parser


def repl(m):
    global base_address
    try:
        num = int(m.group(1), 16)
        if num > 0x100000000:
            retVal = base_address + num - 0x100000000
            return hex(retVal).encode()
        else:
            retVal = base_address + num
            if retVal > 0x200000000:
                retVal -= 0x100000000
            return hex(retVal).encode()
    except:
        return m.group()


def isXcode():
    if "unknown" == os.environ.get("TERM", "unknown"):
        return True
    return False
