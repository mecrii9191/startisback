// run as admin

const path = require('path');
const fs = require('fs');
const regedit = require('regedit').promisified;
 
const randomHex = (size) => [ ...Array(size) ].map(() => Math.floor(Math.random() * 16).toString(16));
 
// PATCH DATA
const PROGRAM_PATHS = [ 'C:\\Program Files (x86)\\StartIsBack', 'C:\\Program Files\\StartIsBack' ];
const PATCHES = { // offset is unused! remove in code
    'StartIsBackCfg.exe': [
        // rel call -> nop
        { name: 'license', pattern: '66 BE AB FF E8 ? ? ? ? 33 C0', rep: '66 BE AB FF 90 90 90 90 90 33 C0', offset: 0 }
    ],
    'StartIsBack32.dll': [
        // inc ret
        { name: 'sibcheck', pattern: '55 8B EC 81 EC 9C 00 00 00 56 6A 08 68 9B', rep: 'B0 01 C3', offset: 0 }
    ],
    'StartIsBack64.dll': [
        // [r8]=1, inc ret
        { name: 'sibcheck', pattern: '40 53 56 57 41 56 48 81 EC F8 00 00 00 49 8B F0', rep: '41 C7 00 01 00 00 00 B0 01 C3', offset: 0 }
    ],
};
const REGISTRY_PATCHES = {
    'HKCU\\SOFTWARE\\StartIsBack\\License': {
        LicenseHash: {
            value: randomHex(32).join(''),
            type: 'REG_SZ'
        },
        ActivationData: {
            value: randomHex(128).map(x => Number(x.charCodeAt(0).toString(10))),
            type: 'REG_BINARY'
        }
    }
};
 
const parseHexString = (hex) => {
    return hex.split(' ').map((x) => String.fromCharCode(parseInt(x, 16))).join('');
}
 
const signatureToRegex = (sig) => {
    const singleByte = '.'; 
    return sig.split(' ').map((x) => x === '?' ? singleByte : '\\u00' + x).join('');
}
 
const findSignature = ({ data }, sig) => {
    const result = new RegExp(sig.pattern, 's').exec(data);
    
    if (result?.index) {
        return result.index; 
    }
    
    return -1;
}
 
class PatchSignature {
    constructor(pattern, name, offset) {
        this.pattern = signatureToRegex(pattern);
        this.name = name;
        this.offset = offset;
    }
}
 
class Patch {
    constructor(file, entry, rep) {
        this.pattern = new PatchSignature(entry.pattern, entry.name, entry.offset);
        this.rep = parseHexString(rep);
        this.file = file;
    }
    
    applyPatch() {
        const offset = findSignature(this.file, this.pattern);
        if (offset < 0) {
            return -1;
        }
        
        const endOffset = offset + this.rep.length;
        
        if (this.file != null) {
            this.file.data = this.file.data.split('');
            this.file.data.splice(offset, this.rep.length, ...this.rep);
            this.file.data = this.file.data.join('');
        }
        else {
            return -1;
        }
        
        return offset;
    }
}
 
class File {
    constructor(path) {
        this.path = path;
        this.data = fs.readFileSync(path, { encoding: 'latin1' });
    }
    
    saveFile() {
        fs.writeFileSync(this.path, this.data, { encoding: 'latin1', flag: 'w' });
    }
}
 
const main = async () => {
    // patch PE
    let patched = false;
    const selected = PROGRAM_PATHS.find((path) => fs.existsSync(path));
 
    const processPatches = (filename, entry) => {
        const filePath = path.join(selected, filename);
        console.log('patching', filePath);
        const newFile = new File(filePath);
        for (const patch of entry) {
            const newPatch = new Patch(newFile, patch, patch.rep).applyPatch();
            if (newPatch < 0) {
                patched = true;
            }
            
            console.log('patch!', newPatch);
        }
        
        if (!patched) {
            newFile.saveFile();
        }
    }
    
    for (const [ filename, entry ] of Object.entries(PATCHES)) {
        processPatches(filename, entry);
    }
    
    if (patched) {
        console.log('looks like the files already been patched! nothing applied');
    }
    
    // patch registry
    for (const [ key, values ] of Object.entries(REGISTRY_PATCHES)) {
        await regedit.createKey(key);
        await regedit.putValue({ [ key ]: values });
    }
};
 
main();
