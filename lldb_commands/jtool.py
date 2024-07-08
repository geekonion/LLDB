
import lldb
import os
import shlex
import subprocess

ds_jtool_dict = {}
base_address = None


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

    is_xcode = isXcode()
    target = exe_ctx.GetTarget()
    args = shlex.split(command)
    executablePath = None
    module = None

    if len(args) >= 1:
        name_or_addr = None
        for arg in args:
            if not arg.startswith('-'):
                if name_or_addr:
                    result.SetError("more than one filepath were found")
                    return
                else:
                    name_or_addr = arg

        if name_or_addr:
            module = target.module[name_or_addr]
            if not module:
                if name_or_addr.isdigit():
                    address = int(name_or_addr)
                else:
                    try:
                        address = int(name_or_addr, 16)
                    except:
                        result.SetError("\"{}\" not found".format(name_or_addr))
                        return

                addr = target.ResolveLoadAddress(address)
                module = addr.GetModule()
                if not module or not module.IsValid():
                    result.SetError("Unable to find module for address {:#x}".format(address))
                    return

    cputype_str = None
    if module:
        executablePath = module.GetFileSpec().fullpath

        result.AppendMessage('module path: {}\n'.format(executablePath))

        cputype_str = get_cputype_string(target, module)
        if cputype_str is None:
            result.SetError("Unable to parse cputype, tell Derek about this")
            return

    proc_args = []
    if not is_xcode:
        proc_args.append("JCOLOR=1")

    global ds_jtool_dict
    ds_jtool_path = ds_jtool_dict[prog]
    proc_args.append(ds_jtool_path)
    if len(args) > 0:
        if prog == 'jtool' and cputype_str:
            proc_args.append("-arch")
            proc_args.append(cputype_str)

        if executablePath:
            args[-1] = "\"{}\"".format(executablePath)

        proc_args.extend(args)

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


def isXcode():
    if "unknown" == os.environ.get("TERM", "unknown"):
        return True
    return False


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


def get_cputype_string(target, module):
    global base_address
    header_addr = module.GetObjectFileHeaderAddress().GetLoadAddress(target)

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
