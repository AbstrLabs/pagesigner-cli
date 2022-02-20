import { RSA_PKCS1_OAEP_PADDING } from 'constants';
import fs from 'fs/promises'
import path from 'path'
import { pubkeyPEM2raw } from './pagesigner/core/utils.js'

function buf2ocaml(name, buf) {
    let ret = `${buf.length} let ${name} = [|`;
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

function buf2mps(name,buf) {
    let ret = `${buf.length}\n`
    ret+= 'long '+ name
    ret+='[] = {'
    for (let e of buf) {
        ret+=e
        ret+=', '
    }
    ret+='};'
    return ret
}

function padding(a) {
    let length = a.length
    let n = Math.floor(length/64)
    let mod = length%64
    let ret_length = mod == 63 ? ((n+2) * 64) : ((n+1) * 64)
    let ret = Buffer.alloc(ret_length)
    for(let i = 0; i < length; i++) {
        ret[i] = a[i]
    }
    ret[length] = 0x80
    for(let i = length+1; i < ret_length - 4; i++) {
        ret[i]=0
    }
    let l = length*8
    for(let i=ret_length-4;i<ret_length;i++){
        let j = ret_length-i-1
        j=(l>>(j*8))&0xff
        ret[i]=j
    }
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
    let serverEcPubkey = Buffer.from(pgsg['server pubkey for ECDHE'], 'base64')

    let notary_pubkey = Buffer.from(pubkeyPEM2raw
(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAp3iALChsj8lOkEpY1F5BeCMcyd6
282weDfsNf8lMYi7xEVVVq0W+is27cCnHZAc0resZHTdX4KoSrFgehhPcA==
-----END PUBLIC KEY-----
`))
    let session_sig = Buffer.from(pgsg['session signature'], 'base64')
    let esmk = Buffer.from(pgsg['ephemeral signed by master key'], 'base64')

    let server_records = Buffer.concat([server_records0, server_records1])
    console.log(server_records)
    console.log(server_records.length)
    server_records = padding(server_records)
    console.log(server_records.toString('hex'))


    let tbs1 = Buffer.from([78,229,69,181,197,187,112,88,195,46,153,110,137,145,27,229,83,200,16,147,76,9,19,82,100,78,117,227,182,59,16,61,83,152,214,62,216,167,14,170,240,43,95,16,47,221,33,79,235,152,27,227,17,133,59,62,61,234,79,219,215,96,228,15,6,0,197,213,222,110,152,193,193,203,117,218,90,168,201,175,101,161,45,33,232,116,140,114,238,197,61,237,245,238,129,205,0,0,0,0,0,0,0,1,23,3,3,0,124,0,0,0,39,16,230,12,35,129,42,248,127,107,13,234,149,191,133,42,130,208,246,73,195,43,214,200,243,62,173,91,44,177,118,68,149,19,117,18,232,92,125,145,136,186,170,135,247,30,80,7,218,233,0,121,19,209,213,221,197,172,189,36,143,145,123,44,28,18,106,116,206,154,24,108,118,187,162,96,179,138,117,3,65,223,116,5,11,100,56,204,102,40,132,215,181,87,132,155,82,12,18,101,65,13,121,195,175,184,240,37,190,0,115,200,57,157,184,184,69,226,38,76,250,101,127,169,0,0,0,0,0,0,0,0,0,0,0,104,0,0,0,0,0,0,3,224,4,164,203,47,187,53,92,172,243,181,58,31,142,159,18,250,191,225,4,171,209,165,163,17,246,103,179,173,126,58,229,72,93,114,45,111,137,141,27,154,132,249,241,14,237,36,223,188,231,107,249,148,191,20,54,162,144,217,228,64,31,97,186,54,81,37,82,131,170,184,138,88,135,165,222,179,130,207,88,4,72,204,98,174,55,170,44,113,181,10,194,114,5,75,203,119,201,221,45,193,122,173,194,148,87,58,84,44,101,245,190,146,109,45,39,48,93,87,248,86,137,157,18,224,94,169,206,35,138,231,117,12,83,252,46,173,33,0,0,0,0,97,191,78,78])
    console.log(buf2mps("tbs1", tbs1))
    let tbs1_padded = padding(tbs1)
    console.log(buf2mps("tbs1_padded", tbs1_padded))

    
    // TODO: real preprocess is save bytes to files. And load files from ocaml. This version is ocaml code generation
    console.log(buf2mps("server_records0", server_records0))
    console.log(buf2mps("server_records1", server_records1))
    console.log(buf2mps("server_records", server_records))
    console.log(buf2mps("client_cwk_share", client_cwk_share))
    console.log(buf2mps("client_civ_share", client_civ_share))
    console.log(buf2mps("client_swk_share", client_swk_share))
    console.log(buf2mps("client_siv_share", client_siv_share))
    console.log(buf2mps("client_pms_share", client_pms_share))
    console.log(buf2mps("client_req_cipher", client_req_cipher))
    console.log(buf2mps("notary_cwk_share", notary_cwk_share))
    console.log(buf2mps("notary_civ_share", notary_civ_share))
    console.log(buf2mps("notary_swk_share", notary_swk_share))
    console.log(buf2mps("notary_siv_share", notary_siv_share))
    console.log(buf2mps("notary_pms_share", notary_pms_share))
    console.log(buf2mps("notary_time", notary_time))
    console.log(buf2mps("ephemeral_pubkey", ephemeral_pubkey))
    console.log(buf2mps("ephemeral_pubkey_valid_from", ephemeral_pubkey_valid_from))
    console.log(buf2mps("ephemeral_pubkey_valid_until", ephemeral_pubkey_valid_until))
    console.log(buf2mps("notary_pubkey", notary_pubkey))
    console.log(buf2mps("session_sig", session_sig))
    console.log(buf2mps("esmk", esmk))
    console.log(buf2mps("serverEcPubkey", serverEcPubkey))

}

main()