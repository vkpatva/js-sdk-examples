/* eslint-disable prefer-const */
/* eslint-disable prettier/prettier */
import { AuthDataPrepareFunc, AuthHandler, base64ToBytes, CircuitId, core, CredentialRequest, CredentialStatusType, DataPrepareHandlerFunc, EthStateStorage, FetchHandler, IdentityCreationOptions, IProofService, PackageManager, PlainPacker, ProofService, StateVerificationFunc, VerificationHandlerFunc, W3CCredential, ZKPPacker } from "@0xpolygonid/js-sdk";
import { initCircuitStorage, initInMemoryDataStorageAndWallets } from "./walletSetup";
import axios from "axios";
import { proving, ZKProof } from "@iden3/js-jwz";
import { Base64 } from "js-base64";
const rhsUrl = process.env.RHS_URL as string;


const defaultNetworkConnection = {
    rpcUrl: process.env.RPC_URL as string,
    contractAddress: '0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124',
};

export const defaultEthConnectionConfig = [{
    url: process.env.RPC_URL as string,
    defaultGasLimit: 600000,
    minGasPrice: '0',
    maxGasPrice: '100000000000',
    confirmationBlockCount: 5,
    confirmationTimeout: 600000,
    contractAddress: '0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124',
    receiptTimeout: 600000,
    rpcResponseTimeout: 5000,
    waitReceiptCycleTime: 30000,
    waitBlockCycleTime: 3000,
    chainId: 80002
}];

export const defaultIdentityCreationOptions: IdentityCreationOptions = {
    method: core.DidMethod.iden3,
    blockchain: core.Blockchain.Polygon,
    networkId: core.NetworkId.Amoy,
    revocationOpts: {
        type: CredentialStatusType.Iden3commRevocationStatusV1,
        id: "https://rhs-staging.polygonid.me"
    },
    seed: Uint8Array.from(Buffer.from([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 26, 26, 26, 26, 26, 28
    ])),
};

export const defaultIdentityCreationOptions2: IdentityCreationOptions = {
    method: core.DidMethod.PolygonId,
    blockchain: core.Blockchain.Polygon,
    networkId: core.NetworkId.Amoy,
    revocationOpts: {
        type: CredentialStatusType.Iden3commRevocationStatusV1,
        id: rhsUrl
    },
    seed: Uint8Array.from(Buffer.from([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 26, 26, 26, 26, 26, 27
    ])),
};

function createCredential(did: core.DID) {
    console.log("=================creating Credential============");
    const credentialRequest: CredentialRequest = {
        credentialSchema:
            'https://raw.githubusercontent.com/vkpatva/jsonschema/refs/heads/main/schema.json',
        type: 'coinvise',
        credentialSubject: { is_user: true, id: did.string() },
        revocationOpts: {
            type: CredentialStatusType.Iden3commRevocationStatusV1,
            id: process.env.RHS_URL as string,
        }
    };
    return credentialRequest;
}

const issueCredential = async () => {
    console.log("issuing credential using issuer node")
    let dataStorage, credentialWallet, identityWallet;

    ({ dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
        defaultNetworkConnection
    ));


    const circuitStorage = await initCircuitStorage();


    console.log("creating user identity")
    const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
        ...defaultIdentityCreationOptions
    });
    console.log("userDID", userDID.string())
    console.log("authBJJCredentialUser", authBJJCredentialUser)
    console.log("\n\n\n\n\n")

    console.log("------------msgbytes-------------");


    // const msgBytes = await fetch(decodeURIComponent("https%3A%2F%2Fissuer.zkred.tech%2Fv2%2Fqr-store%3Fid%3Dcd65dd83-51ec-4f88-ac87-e4a70ec1cf67%26issuer%3Ddid%3Aiden3%3Apolygon%3Aamoy%3AxJAQoVCf7FpDV3akwmQMy5EULPVsbcnYEaCd37N2F"))
    //     .then(
    //         (res) => res.arrayBuffer()
    //     ).then(
    //         (res) => new Uint8Array(res)
    //     );

    // console.log(msgBytes)

    // // const result = await approveMethod(msgBytes);

    // let proofService = new ProofService(identityWallet, credentialWallet,
    //     circuitStorage, new EthStateStorage(defaultEthConnectionConfig[0]),
    //     { ipfsGatewayURL: "https://ipfs.io" });

    // let packageMgr = await getPackageMgr(
    //     await circuitStorage.loadCircuitData(CircuitId.AuthV2),
    //     proofService.generateAuthV2Inputs.bind(proofService),
    //     proofService.verifyState.bind(proofService)
    // );
    // const authHandler = new AuthHandler(packageMgr, proofService);

    // const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    // console.log(authRes)
    // console.log(JSON.stringify(authRes));

    // const credentials: W3CCredential[] | void = await axios
    //     .post(`${authRes.authRequest.body.callbackUrl}`, authRes.token)
    //     .then(async (response) => {
    //         console.log("calling callback url")
    //         console.log(JSON.stringify(response.data));
    //         const newPayload = Base64.encode(JSON.stringify(response.data));

    //         const newMsgBytes = base64ToBytes(newPayload);
    //         console.log("newMsgBytes", newMsgBytes)
    //         let fetchHandler = new FetchHandler(packageMgr);
    //         const credentials = await fetchHandler.handleCredentialOffer(newMsgBytes);
    //         return credentials;

    //     })
    //     .catch((error) => {
    //         console.log("error")
    //         console.log("error", error)
    //     });
    // if (credentials) {
    //     await dataStorage.credential.saveAllCredentials([credentials[0]]);
    // }

    // console.log("===================credential stored====================")
    // const creds = await credentialWallet.list();
    // console.log("creds", creds)
    // console.log("\n\n\n\n\n")


    // //-----ISSUING SECOND CREDENTIAL----------


    // const msgBytes2 = await fetch(decodeURIComponent("https%3A%2F%2Fissuer.zkred.tech%2Fv2%2Fqr-store%3Fid%3D691935a6-500d-48e9-9a91-1e2063a20176%26issuer%3Ddid%3Aiden3%3Apolygon%3Aamoy%3AxJAQoVCf7FpDV3akwmQMy5EULPVsbcnYEaCd37N2F"))
    //     .then(
    //         (res) => res.arrayBuffer()
    //     ).then(
    //         (res) => new Uint8Array(res)
    //     );


    // // const result2 = await approveMethod(msgBytes);



    // const authRes2 = await authHandler.handleAuthorizationRequest(userDID, msgBytes2);
    // console.log(authRes2)


    // const credentials2: W3CCredential[] | void = await axios
    //     .post(`${authRes2.authRequest.body.callbackUrl}`, authRes2.token)
    //     .then(async (response) => {
    //         console.log("calling callback url")
    //         console.log(JSON.stringify(response.data));
    //         const newPayload = Base64.encode(JSON.stringify(response.data));

    //         const newMsgBytes = base64ToBytes(newPayload);
    //         console.log("newMsgBytes", newMsgBytes)
    //         let fetchHandler = new FetchHandler(packageMgr);
    //         const credentials = await fetchHandler.handleCredentialOffer(newMsgBytes);
    //         return credentials;

    //     })
    //     .catch((error) => {
    //         console.log("error")
    //         console.log("error", error)
    //     });
    // if (credentials2) {
    //     await dataStorage.credential.saveAllCredentials([credentials2[0]]);
    // }

    // console.log("Credential 2 :  \\n\n\n\n", JSON.stringify(credentials2));
    // console.log("===================credential stored====================")
    // const creds2 = await credentialWallet.list();
    // console.log("creds", creds2)
    // console.log("\n\n\n\n\n")



    /// proving credential

    const proofService2: IProofService = new ProofService(
        identityWallet,
        credentialWallet,
        circuitStorage,
        dataStorage.states,
    );



    // console.log("verifying credential")

    // const proofReq = {
    //     "circuitId": "credentialAtomicQuerySigV2",
    //     "id": 1736664272,
    //     "query": {
    //         "allowedIssuers": [
    //             "*"
    //         ],
    //         "context": "https://raw.githubusercontent.com/vkpatva/jsonschema/refs/heads/main/testing-file.json",
    //         "type": "testingschema",
    //         "credentialSubject": {
    //             "attribute.weight": {}
    //         }
    //     }
    // }
    // const findCred: W3CCredential[] = await credentialWallet.findByQuery(proofReq.query);
    // console.log("findCred", findCred)
    // console.log("length of the credentials", findCred.length)

    // console.log("cred1 : \n\n\n\n", findCred[0])
    // console.log("cred2 : \n\n\n\n", findCred[1])
    // if (findCred.length > 0) {
    //     const revocationStatus = await credentialWallet.getRevocationStatusFromCredential(findCred[0]);
    //     console.log("revocationStatus", revocationStatus)
    // }

    // ----------successful verification-------
    // const proof = await proofService2.generateProof(proofReq, userDID, { skipRevocation: true, credential: findCred[1] });
    // console.log("proof", JSON.stringify(proof))

    const proof = { "id": 1737103901, "circuitId": "credentialAtomicQuerySigV2", "proof": { "pi_a": ["7753757663693572813314186228009634312947083487413998009342428674388472209408", "17885455323958167585272753242043129941390897333180274628055462444083806034641", "1"], "pi_b": [["20652455151828609556053718110954014885391537234150237142441250512052290151420", "3836016131759169381692883753621363157721254462502282452873499166525214065072"], ["1535724877851854112935245041264281393539419294066174115053131524802349225463", "14376918514235931981732031163735753408128641326098452485138681993274929187843"], ["1", "0"]], "pi_c": ["9684944207762810229145168784374010495599714088169091588876026663609305253739", "9582013793453849139112166794738082847972650784156080358878718934711352060100", "1"], "protocol": "groth16" }, "pub_signals": ["1", "23349790305395415308645893478508627717755802615400038534898729198191317761", "5940228189662180388941582307130471664071836093179686380207442629854858212697", "1737103901", "21340553769467552806739236547301420065997532869711745005630436968511181569", "0", "21697020259584286631158728378529449796249596621015956869408030342593052143650", "1737103930", "153923982489532153299371786123663592885", "0", "4792130079462681165428511201253235850015648352883240577315026477780493110675", "0", "1", "10656670712789185448149774401919386926059264501540007353959018271874703607999", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"] }
    const sigProofOk = await proofService2.verifyProof(
        proof as unknown as ZKProof,
        CircuitId.AtomicQuerySigV2
    );
    console.log("sigProofOk", sigProofOk)

}


const jsSdkCredential = async () => {
    console.log("issuing credential using js-sdk")
    let dataStorage, credentialWallet, identityWallet, issuerDataStorage, issuerCredentialWallet, issuerIdentityWallet;


    ({ dataStorage, credentialWallet, identityWallet } = await initInMemoryDataStorageAndWallets(
        defaultNetworkConnection
    ));

    ({ dataStorage: issuerDataStorage, credentialWallet: issuerCredentialWallet, identityWallet: issuerIdentityWallet } = await initInMemoryDataStorageAndWallets(
        defaultNetworkConnection
    ));
    const circuitStorage = await initCircuitStorage();


    console.log("creating user identity")
    const { did: userDID, credential: authBJJCredentialUser } = await identityWallet.createIdentity({
        ...defaultIdentityCreationOptions
    });
    console.log("userDID", userDID.string())
    console.log("authBJJCredentialUser", authBJJCredentialUser)
    console.log("\n\n\n\n\n")



    console.log("creating issuer identity")
    const { did: issuerDid, credential: issuerCredential } = await issuerIdentityWallet.createIdentity({
        ...defaultIdentityCreationOptions2
    });
    console.log("issuerDid", issuerDid.string())
    console.log("issuerCredential", issuerCredential)
    console.log("\n\n\n\n\n")

    console.log("issuing credential to : ", userDID.string(), "from : ", issuerDid.string())


    console.log("=============issuing credential=============")
    const credentialRequest = createCredential(userDID);
    console.log("credentialRequested", credentialRequest)
    console.log("\n\n\n\n\n")

    const credentialResponse = await issuerIdentityWallet.issueCredential(issuerDid, credentialRequest);
    console.log(JSON.stringify(credentialResponse, null, 2))
    console.log("\n\n\n\n\n")

    console.log("===================storing credential====================")
    console.log("storing credential to : ", userDID.string())
    await dataStorage.credential.saveCredential(credentialResponse);
    console.log("===================credential stored====================")
    const creds = await credentialWallet.list();
    console.log("creds", creds)
    console.log("\n\n\n\n\n")

    const proofService: IProofService = new ProofService(
        identityWallet,
        credentialWallet,
        circuitStorage,
        dataStorage.states,
    );

    console.log("verifying credential")

    const proofReq = {
        circuitId: CircuitId.AtomicQuerySigV2,
        optional: false,
        id: 1732978620,
        query: {

            allowedIssuers: [
                "*"
            ],
            context: "https://raw.githubusercontent.com/vkpatva/jsonschema/refs/heads/main/json-ld.json",
            type: "coinvise",
            credentialSubject: {
                is_user: {}
            }
        }
    }

    const proof = await proofService.generateProof(proofReq, userDID, { skipRevocation: true });
    console.log("proof", proof)
    const sigProofOk = await proofService.verifyProof(
        proof as unknown as ZKProof,
        CircuitId.AtomicQuerySigV2
    );
    console.log("sigProofOk", sigProofOk)

}

async function approveMethod(msgBytes: any) {
    console.log(msgBytes);
}

async function main(choice: string) {
    switch (choice) {

        case 'issuerNode':
            await issueCredential();
            break;
        case 'js-sdk': {
            await jsSdkCredential();
            break;
        }
        default:
            await issueCredential();
            break;
    }
}

async function getPackageMgr(circuitData: { verificationKey: any; provingKey: any; wasm: any; }, prepareFn: AuthDataPrepareFunc, stateVerificationFn: StateVerificationFunc) {
    const authInputsHandler = new DataPrepareHandlerFunc(prepareFn);
    const verificationFn = new VerificationHandlerFunc(stateVerificationFn);
    const mapKey = proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
    const verificationParamMap = new Map([
        [
            mapKey,
            {
                key: circuitData.verificationKey,
                verificationFn
            }
        ]
    ]);

    const provingParamMap = new Map();
    provingParamMap.set(mapKey, {
        dataPreparer: authInputsHandler,
        provingKey: circuitData.provingKey,
        wasm: circuitData.wasm
    });

    const mgr = new PackageManager();
    const packer = new ZKPPacker(provingParamMap, verificationParamMap);
    const plainPacker = new PlainPacker();
    mgr.registerPackers([packer, plainPacker]);

    return mgr;
}
(async function () {
    const args = process.argv.slice(2);
    await main(args[0]);
})();