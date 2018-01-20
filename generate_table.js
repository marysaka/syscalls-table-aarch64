const child_process= require('child_process')
const ctags = require('ctags')
const deadsync = require('deasync')
const fs = require('fs')
const http = require('https')
const rimraf = require('rimraf');
const args = process.argv.slice(2);

path = "/tmp/"

if (args.length != 1)
{
    console.log("Usage: %s linuxVersion", process.argv.join(' '))
}
else
{
    version = args[0]
    linuxPath = path + "linux-" + version
    linuxURL = "https://www.kernel.org/pub/linux/kernel/v4.x/linux-" + version + ".tar.xz"
    console.log("Downloading Linux %s...", version)
    download(linuxPath + ".tar.xz", linuxURL, (err) => {
        if (err)
            throw err;
        child_process.execSync("tar xf " + linuxPath + ".tar.xz" + " -C " + path)
        process_files();
    })
}

function process_files()
{
    // Generate tags for syscalls
    console.log("Generating syscall tags...")
    child_process.execSync("ctags -f syscalls_tags --fields=afmikKlnsStz --c-kinds=+ps-d " + linuxPath + "/include/linux/syscalls.h")
    console.log("Generating kernel tags (may take some time)...")
    child_process.execSync("ctags -f kernel_tags --fields=afmikKlnsStz --c-kinds=+ps-d -R " + linuxPath)
    
    
    // Generate base syscalls
    syscalls = fs.readFileSync(linuxPath + "/arch/arm/tools/syscall.tbl", 'utf-8').split('\n').map(line => {
        data = line.replace(/\s+/g,'\t').split('\t')
        if (data[0] == '#' | data[0] == '')
            return null;
        return {num: data[0], abi: data[1], name: data[2], entry_point: data[3], compat_entry_point: data[4], args: [], syscall_id: -1}
    }).filter(data => data != null);
    
    syscall_uapi = fs.readFileSync(linuxPath + "/include/uapi/asm-generic/unistd.h", 'utf-8')
    syscalls_id = {}
    
    // FIXME: improve detection by matching the defines
    // Get the real id of the syscalls
    pattern = /^\#define (.*) (.*)\n__SYSCALL\((.*), (.*)\)$/gm;
    populate_syscalls_id(pattern, syscall_uapi);
    
    // Get the real id of the compat syscalls
    pattern = /^\#define (.*) (.*)\n__SC_COMP\((.*), (.*), (.*)\)$/gm;
    populate_syscalls_id(pattern, syscall_uapi);
    
    pattern = /^\#define (.*) (.*)\n__SC_3264\((.*), (.*), (.*)\)$/gm;
    populate_syscalls_id(pattern, syscall_uapi);
    
    tags = []
    tagStream = ctags.createReadStream('syscalls_tags')
    tagStream.on('data', (inputTags) => {
        tags = tags.concat(inputTags)
    })
    tagStream.on('end', populate_syscalls_signatures);
}

function download(dest, url, cb)
{
    var f = fs.createWriteStream(dest);
    http.get(url, (res) => {
        if (res.statusCode != 200)
        {
            cb("Error during download, status code: " + res.statusCode);
        }
        res.pipe(f)
        f.on('finish', () => {
            f.close(cb);
        })
    }).on('error', function(err) {
        fs.unlink(dest);
        if (cb)
            cb(err.message);
      })
}

function populate_syscalls_id(pattern, data)
{
    while (match = pattern.exec(data)) {
        syscalls_id[match[4].trim()] = match[2];
    }
}

function populate_syscalls_signatures()
{
    tags = tags.filter(tag => tag.name.startsWith('sys_'))
    for (tag of tags)
    {
        for (syscall of syscalls)
        {
            if (tag.name == syscall.entry_point)
            {
                signature = tag.fields.signature.substring(1, tag.fields.signature.length - 1)
                if (signature != "void")
                    syscall.args = signature.split(', ')
                syscall.syscall_id = parseInt(syscalls_id[syscall.entry_point], 10)
                populate_syscalls_definition(syscall)
                break;
            }
        }
    }
    finalize();
}

function populate_syscalls_definition(syscall)
{
    sync = true
    tagName = "SYSCALL_DEFINE" + syscall.args.length
    toFind = "/^SYSCALL_DEFINE" + syscall.args.length + "(" + syscall.entry_point.replace('sys_', '')
    ctags.findTags('kernel_tags', tagName, (err, inputTags) => {
        for (var tag of inputTags)
        {
            if (tag.kind == "function" && tag.pattern.startsWith(toFind))
            {
                syscall.source = {file: tag.file.replace(linuxPath, '').substring(1), line: tag.lineNumber}
                break;
            }
        }
        if (syscall.source == null)
            console.warn("Warning: syscall " + syscall.name + " definition not found")
        sync = false
    });
    while(sync) {deadsync.sleep(10);}
}

function finalize()
{
    console.log("Finalize")

    dead_syscalls = syscalls.filter(syscall => syscall.syscall_id == -1)
    if (dead_syscalls.length != 0)
    {
        console.warn("Found " + dead_syscalls.length + " dead syscalls:")
        for (syscall of dead_syscalls)
        {
            console.warn(JSON.stringify(syscall));
        }
    }

    orphan_syscalls = syscalls.filter(syscall => isNaN(syscall.syscall_id))
    if (orphan_syscalls.length != 0)
    {
        console.warn("Found " + orphan_syscalls.length + " orphan syscalls:")
        for (syscall of orphan_syscalls)
        {
            console.warn(JSON.stringify(syscall));
        }
    }

    syscalls = syscalls.filter(syscall => syscall.syscall_id != -1 && !isNaN(syscall.syscall_id))
    fs.writeFile('aarch64_syscalls.json', JSON.stringify({version: version, syscalls: syscalls}, null, 2), (err) => {
        if (err) throw err;
        console.log('aarch64_syscalls.json has been saved!');
    })
    console.log("Removing temporary files...")
    fs.unlinkSync(linuxPath + ".tar.xz")
    rimraf.sync(linuxPath)
    fs.unlinkSync("kernel_tags")
    fs.unlinkSync("syscalls_tags")
}