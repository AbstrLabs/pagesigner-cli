#!/usr/bin/env -S node --experimental-wasm-simd

const ver = process.versions.node.split('.');
if (Number(ver[0]) < 16 || (Number(ver[0]) == 16 && Number(ver[1]) < 5)){
    console.log("Error: the minimum supported node.js version is 16.5.0");
    console.log("Detected version: ", process.versions.node);
    process.exit(1);
}

import {assert, b64decode, b64encode} from './pagesigner/core/utils.js'
import {parse_certs} from './pagesigner/core/verifychain.js';
import {verifyNotary, getURLFetcherDoc} from './pagesigner/core/oracles.js';
import {FirstTimeSetup} from './pagesigner/core/FirstTimeSetup.js';
import {globals} from './pagesigner/core/globals.js';

import * as Path from 'path'
import {fileURLToPath} from 'url'
// __dirname is the directory where we are located
const __dirname = Path.dirname(fileURLToPath(import.meta.url))
// this workaround allows to require() from ES6 modules, which is not allowed by default 
import { createRequire } from 'module'
const require = createRequire(import.meta.url)

const pkijs = require("pkijs"); 
const { Crypto } = require("@peculiar/webcrypto");
const crypto = new Crypto();
global.crypto = crypto;
pkijs.setEngine("newEngine", crypto, new pkijs.CryptoEngine({ name: "", crypto: crypto, subtle: crypto.subtle }))

global.CBOR  = require('cbor-js')
import * as COSE from './pagesigner/core/third-party/coseverify.js'
global.COSE = COSE
// replace browser's fetch
import {fetch} from 'undici'
global.fetch = fetch
const http = require('http');
// keepAliveAgent tells fetch to reuse the same source port 
global.keepAliveAgent = new http.Agent({keepAlive: true});
// replace browser's DOMParser
import DOMParser from 'universal-dom-parser'
global.DOMParser = DOMParser
const fs = require('fs')
global.fs = fs
global.sodium= require('libsodium-wrappers-sumo');
global.nacl = require('tweetnacl')
global.ECSimple = require('simple-js-ec-math')
global.bcuNode = require('bigint-crypto-utils')
global.fastsha256 = require('fast-sha256');

// this must be imported dynamically after global.bcuNode becomes available
const TLSNotarySession = (await import('./pagesigner/core/TLSNotarySession.js')).TLSNotarySession;
const Main = (await import('./pagesigner/core/Main.js')).Main;

// always return 0 when browser calls performance.now()
global.performance = {'now':function(){return 0;}};
// when browser asks for a resource URL, return a full path
global.chrome = {'extension':{'getURL': (url) => Path.join(__dirname, 'pagesigner', url)}}

// override some methods of Socket
import {Socket} from './pagesigner/core/Socket.js';
const net = require('net');
class SocketNode extends Socket{
    constructor(server, port){
        super(server, port)
        this.sock = new net.Socket();
        const that = this
        this.sock.on('data', function(d) {
            that.buffer = Buffer.concat([that.buffer, d])
        });
    }
    async connect(){
        await this.sock.connect(this.port, this.name);
        setTimeout(function() {
            if (! this.wasClosed) this.close();
        }, this.lifeTime);
        return 'ready';
    }
    async send(d) {
        var data = new Buffer.from(d)
        this.sock.write(data);
    }
    async close() {
        this.sock.destroy()
    }
}
global.SocketNode = SocketNode

// a drop-in replacement for WebWorker
const { Worker, parentPort } = require('worker_threads');
class mWorker extends Worker{
    constructor(url){
        super(url)
        this.onmessage = function(){}
        this.on('message', function(msg){
            this.onmessage(msg)
        })
    }
}
global.Worker = mWorker

// original parseAndAssemble is called with relative paths, we convert them into absolute paths 
import './pagesigner/core/twopc/circuits/casmbundle.js'
CASM.parseAndAssembleOld = CASM.parseAndAssemble
CASM.parseAndAssemble = function(file){
    const fullpath = Path.join(__dirname, 'pagesigner', 'core', 'twopc', 'circuits', file)
    return CASM.parseAndAssembleOld(fullpath)
}


async function createNewSession(host, request, response, date, pgsg, is_imported=false){
    const suffix = is_imported ? "_imported" : ""
    const sessDir = Path.join(__dirname, 'saved_sessions', date + "_" + host + suffix) 
    fs.mkdirSync(sessDir, { recursive: true });   
    fs.writeFileSync(Path.join(sessDir, "request"), request)
    fs.writeFileSync(Path.join(sessDir, "response"), response)
    fs.writeFileSync(Path.join(sessDir, date+".pgsg"), Buffer.from(JSON.stringify(pgsg)))
    return sessDir
}

async function createNotaryJson(path, pgsg){
    const jsonPath = Path.join(path, "notary.json");
    fs.mkdirSync(path, { recursive: true });
    fs.writeFileSync(jsonPath, Buffer.from(JSON.stringify(pgsg)))
    return jsonPath
}


function showUsage(){
    console.log("Usage: ./pgsg-node.js <command> [options] \r\n")
    console.log("where <command> is one of notarize, verify\r\n")
    console.log("Examples:\r\n")
    console.log("./pgsg-node.js notarize example.com --headers headers.txt output")
    console.log("Notarize example.com using HTTP headers from headers.txt\r\n")
    console.log("./pgsg-node.js verify imported.pgsg")
    console.log("Verify a Pagesigner session from imported.pgsg. This will create a session directory with the decrypted cleartext and a copy of the pgsg file.\r\n")
    console.log("\r\n")
    process.exit(0)
}

async function setupNotary(){
    const m = new Main();
    if (globals.useNotaryNoSandbox){
        return await m.queryNotaryNoSandbox(globals.defaultNotaryIP);
    } else {
        const cacheDir = Path.join(__dirname, 'cache')
        const tnPath = Path.join(cacheDir, 'trustedNotary')
        if (fs.existsSync(tnPath)) {
            // load notary from disk
            const obj = JSON.parse(fs.readFileSync(tnPath))
            obj['URLFetcherDoc'] = b64decode(obj['URLFetcherDoc'])
            console.log('Using cached notary from ', tnPath)
            console.log('Notary IP address: ', obj.IP);
            return obj
        } else {
            // fetch and verify the URLFetcher doc
            const URLFetcherDoc = await getURLFetcherDoc(globals.defaultNotaryIP);
            const trustedPubkeyPEM = await verifyNotary(URLFetcherDoc);
            assert(trustedPubkeyPEM != undefined);
            const obj = {
                'IP': globals.defaultNotaryIP,
                'pubkeyPEM': trustedPubkeyPEM,
                'URLFetcherDoc': URLFetcherDoc
              };
            // save the notary to disk
            const objSave = {
                'IP': obj.IP,
                'pubkeyPEM': obj.pubkeyPEM,
                'URLFetcherDoc': b64encode(obj.URLFetcherDoc)
            }
            fs.writeFileSync(tnPath, Buffer.from(JSON.stringify(objSave)))
            return obj
        }
    }
}

async function main (){
    const argv = process.argv
    if (argv[2] === 'notarize') {
        if (argv.length !== 7 || (argv.length == 7 && argv[4] !== '--headers')){
            showUsage();
        }
        const outputPath = argv[6];

        const cacheDir = Path.join(__dirname, 'cache')
        if (! fs.existsSync(cacheDir)) {fs.mkdirSync(cacheDir)};
        const psPath = Path.join(cacheDir, 'parsedCircuits')
        const gbPath = Path.join(cacheDir, 'gatesBlob')

        let circuits
        if (fs.existsSync(psPath)) {
            // load cached serialized circuits
            circuits = JSON.parse(fs.readFileSync(psPath))
        } else {
            // run first time setup
            circuits = await new FirstTimeSetup().start();
            for (const [k, v] of Object.entries(circuits)) {
                circuits[k]['gatesBlob'] = b64encode(circuits[k]['gatesBlob'])
            }
            fs.writeFileSync(psPath, Buffer.from(JSON.stringify(circuits)))
        }
        for (const [k, v] of Object.entries(circuits)) {
            circuits[k]['gatesBlob'] = b64decode(circuits[k]['gatesBlob'])
        }

        // prepare root store certificates
        const rootStorePath = Path.join(__dirname, 'pagesigner', 'core', 'third-party', 'certs.txt')
        await parse_certs(fs.readFileSync(rootStorePath).toString());

        const server = argv[3]
        const headersfile = argv[5]

        // split into lines keeping the delimiter at the end of each line
        const lines = fs.readFileSync(headersfile).toString().split(/(?<=\r\n|\n)/);
        let headers = ''
        let blankLineWasFound = false
        for (let i=0; i < lines.length; i++){
            if (blankLineWasFound){ // keep request body as it is
                headers += lines[i]
            }
            else if (i > 0 && ['\r\n', '\n'].includes(lines[i])){ // a blank line was found
                blankLineWasFound = true
                headers += '\r\n'
            }
            else { // replace whatever delimiter is at the end with /r/n
                headers += lines[i].split(/\r\n|\n/)[0]+ '\r\n'
            }
        }
        if (! blankLineWasFound){
            headers += '\r\n'
        }

        const m = new Main();
        m.trustedOracle = await setupNotary();
        // start the actual notarization
        const session = new TLSNotarySession(
            server, 443, headers, m.trustedOracle, globals.sessionOptions, circuits, null);
        const obj = await session.start();
        obj['title'] = 'PageSigner notarization file';
        obj['version'] = 6;
        if (! globals.useNotaryNoSandbox){
            obj['URLFetcher attestation'] = m.trustedOracle.URLFetcherDoc;
        }
        const [host, request, response, date] = await m.verifyPgsgV6(obj);
        const serializedPgsg = m.serializePgsg(obj);
        // const sessDir = await createNewSession(host, request, response, date, serializedPgsg)
        const jsonPath = await createNotaryJson(outputPath, serializedPgsg);
        console.log('NotaryJson was saved in ', jsonPath)
        process.exit(0)
    }  

    else if (argv[2] === 'verify') {
        if (argv.length !== 4){
            showUsage()
        }
        const pgsgBuf = fs.readFileSync(argv[3])
        const serializedPgsg = JSON.parse(pgsgBuf)
        const m = new Main();
        const pgsg = m.deserializePgsg(serializedPgsg);
        // prepare root store certificates
        const rootStorePath = Path.join(__dirname, 'pagesigner', 'core', 'third-party', 'certs.txt')
        await parse_certs(fs.readFileSync(rootStorePath).toString());
        const [host, request, response, date] = await m.verifyPgsgV6(pgsg);
        const sessDir = await createNewSession(host, request, response, date, serializedPgsg, true)
        console.log('The imported session was verified and saved in ', sessDir)
        process.exit(0)
    }

    else {
        showUsage()
    }
}
main()