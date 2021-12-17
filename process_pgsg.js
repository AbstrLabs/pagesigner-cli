import fs from 'fs/promises'
import path from 'path'

function buf2ocaml(buf) {
    let ret = '[|';
    for(let e of buf) {
        ret+='0x'
        let n = e.toString(16)
        if (e.length < 2) {
            e = '0'+e
        }
        ret+=e
        ret+='; '
    }
    ret+='|]'
    return ret
}

async function main() {
    let pgsgPath = path.resolve(process.argv[process.argv.length-1])
    let pgsg = JSON.parse(await fs.readFile(pgsgPath))
    console.log(Object.keys(pgsg))
    let swkc = pgsg['client server_write_key share']
    let swkn = pgsg['notary server_write_key share']
    swkc = Buffer.from(swkc, 'base64')
    swkn = Buffer.from(swkn, 'base64')
    let swk = swkc.map((b, i) => b ^ swkn[i]);
    console.log(swk)
    console.log(buf2ocaml(swk))
    console.log(swk.toString('hex'))
}

main()