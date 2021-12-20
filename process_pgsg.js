import fs from 'fs/promises'
import path from 'path'
import { pubkeyPEM2raw } from './pagesigner/core/utils.js'

function buf2ocaml(name, buf) {
    let ret = `let ${name} = [|`;
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

    let server_records0 = Buffer.from(pgsg['server response records'][0], 'base64')
    let server_records1 = Buffer.from(pgsg['server response records'][1], 'base64')
    let client_cwk_share = Buffer.from(pgsg['client client_write_key share'], 'base64')
    let client_civ_share = Buffer.from(pgsg['client client_write_iv share'], 'base64')
    let client_swk_share = Buffer.from(pgsg['client server_write_key share'], 'base64')
    let client_siv_share = Buffer.from(pgsg['client server_write_iv share'], 'base64')
    let client_pms_share = Buffer.from(pgsg['client PMS share'], 'base64')
    let client_req_cipher = Buffer.from(pgsg['client request ciphertext'], 'base64')
    let notary_cwk_share = Buffer.from(pgsg['notary client_write_key share'], 'base64')
    let notary_civ_share = Buffer.from(pgsg['notary client_write_iv share'], 'base64')
    let notary_swk_share = Buffer.from(pgsg['notary server_write_key share'], 'base64')
    let notary_siv_share = Buffer.from(pgsg['notary server_write_iv share'], 'base64')
    let notary_pms_share = Buffer.from(pgsg['notary PMS share'], 'base64')
    let notary_time = Buffer.from(pgsg['notarization time'], 'base64')
    let ephemeral_pubkey = Buffer.from(pgsg['ephemeral pubkey'], 'base64')
    let ephemeral_pubkey_valid_from = Buffer.from(pgsg['ephemeral valid from'], 'base64')
    let ephemeral_pubkey_valid_until = Buffer.from(pgsg['ephemeral valid until'], 'base64')
    let notary_pubkey = Buffer.from(pubkeyPEM2raw
(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAp3iALChsj8lOkEpY1F5BeCMcyd6
282weDfsNf8lMYi7xEVVVq0W+is27cCnHZAc0resZHTdX4KoSrFgehhPcA==
-----END PUBLIC KEY-----
`))
    let session_sig = Buffer.from(pgsg['session signature'], 'base64')
    let esmk = Buffer.from(pgsg['ephemeral signed by master key'], 'base64')

    // TODO: real preprocess is save bytes to files. And load files from ocaml. This version is ocaml code generation
    console.log(buf2ocaml("server_records0", server_records0))
    console.log(buf2ocaml("server_records1", server_records1))
    console.log(buf2ocaml("client_cwk_share", client_cwk_share))
    console.log(buf2ocaml("client_civ_share", client_civ_share))
    console.log(buf2ocaml("client_swk_share", client_swk_share))
    console.log(buf2ocaml("client_siv_share", client_siv_share))
    console.log(buf2ocaml("client_pms_share", client_pms_share))
    console.log(buf2ocaml("client_req_cipher", client_req_cipher))
    console.log(buf2ocaml("notary_cwk_share", notary_cwk_share))
    console.log(buf2ocaml("notary_civ_share", notary_civ_share))
    console.log(buf2ocaml("notary_swk_share", notary_swk_share))
    console.log(buf2ocaml("notary_siv_share", notary_siv_share))
    console.log(buf2ocaml("notary_pms_share", notary_pms_share))
    console.log(buf2ocaml("notary_time", notary_time))
    console.log(buf2ocaml("ephemeral_pubkey", ephemeral_pubkey))
    console.log(buf2ocaml("ephemeral_pubkey_valid_from", ephemeral_pubkey_valid_from))
    console.log(buf2ocaml("ephemeral_pubkey_valid_until", ephemeral_pubkey_valid_until))
    console.log(buf2ocaml("notary_pubkey", notary_pubkey))
    console.log(buf2ocaml("session_sig", session_sig))
    console.log(buf2ocaml("esmk", esmk))
}

main()