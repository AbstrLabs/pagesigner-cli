import fs from 'fs/promises'
import path from 'path'

function buf2ocaml(buf) {
    let ret = '[|';
    for(let e of buf) {
        ret+='0x'
        let n = e.toString(16)
        if (n.length < 2) {
            n = '0'+n
        }
        ret+=n
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

    let swic = pgsg['client server_write_iv share']
    let swin = pgsg['notary server_write_iv share']
    swic = Buffer.from(swic, 'base64')
    swin = Buffer.from(swin, 'base64')
    let swi = swic.map((b, i) => b ^ swin[i]);
    let records = pgsg['server response records']

    console.log(swk)
    console.log(buf2ocaml(swk))
    console.log(swk.toString('hex'))
    let rec = Buffer.from(records[0], 'base64').slice(0, 8)
    let zero = Buffer.from([0,0,0,0])
    let aesgcm_iv = Buffer.concat([swi, rec, zero])
    console.log(buf2ocaml(aesgcm_iv))
}

main()