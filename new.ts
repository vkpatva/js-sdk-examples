/* eslint-disable prefer-const */
/* eslint-disable prettier/prettier */
import { AuthDataPrepareFunc, AuthHandler, base64ToBytes, CircuitId, core, CredentialRequest, CredentialStatusType, DataPrepareHandlerFunc, EthStateStorage, FetchHandler, IdentityCreationOptions, IProofService, PackageManager, PlainPacker, ProofQuery, ProofService, StateVerificationFunc, VerificationHandlerFunc, W3CCredential, ZeroKnowledgeProofRequest, ZKPPacker } from "@0xpolygonid/js-sdk";
import { initCircuitStorage, initInMemoryDataStorageAndWallets } from "./walletSetup";
import axios from "axios";
import { ProofData, proving, ZKProof } from "@iden3/js-jwz";
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
    chainId: 80001
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


    const msgBytes = await fetch(decodeURIComponent("https%3A%2F%2Fissuer5.zkred.tech%2Fv2%2Fqr-store%3Fid%3Db491d987-d5a5-4934-9d46-427fad87c7b5%26issuer%3Ddid%3Aiden3%3Apolygon%3Aamoy%3AxC3kP1H11c5EpKrmHXXKSEmkaeim3anmEq8nxcwMd"))
        .then(
            (res) => res.arrayBuffer()
        ).then(
            (res) => new Uint8Array(res)
        );

    console.log(msgBytes)

    const result = await approveMethod(msgBytes);

    let proofService = new ProofService(identityWallet, credentialWallet,
        circuitStorage, new EthStateStorage(defaultEthConnectionConfig[0]),
        { ipfsGatewayURL: "https://ipfs.io" });

    let packageMgr = await getPackageMgr(
        await circuitStorage.loadCircuitData(CircuitId.AuthV2),
        proofService.generateAuthV2Inputs.bind(proofService),
        proofService.verifyState.bind(proofService)
    );
    const authHandler = new AuthHandler(packageMgr, proofService);

    const authRes = await authHandler.handleAuthorizationRequest(userDID, msgBytes);
    console.log(authRes)
    console.log(JSON.stringify(authRes));

    const credentials: W3CCredential[] | void = await axios
        .post(`${authRes.authRequest.body.callbackUrl}`, authRes.token)
        .then(async (response) => {
            console.log("calling callback url")
            console.log(JSON.stringify(response.data));
            const newPayload = Base64.encode(JSON.stringify(response.data));

            const newMsgBytes = base64ToBytes(newPayload);
            console.log("newMsgBytes", newMsgBytes)
            let fetchHandler = new FetchHandler(packageMgr);
            const credentials = await fetchHandler.handleCredentialOffer(newMsgBytes);
            return credentials;

        })
        .catch((error) => {
            console.log("error")
            console.log("error", error)
        });
    if (credentials) {
        await dataStorage.credential.saveAllCredentials([credentials[0]]);
    }

    console.log("===================credential stored====================")
    const creds = await credentialWallet.list();
    console.log("creds", creds)
    console.log("\n\n\n\n\n")

    const proofService2: IProofService = new ProofService(
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

    const proof = await proofService2.generateProof(proofReq, userDID, { skipRevocation: true });
    console.log("proof", proof)
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
        }
        default:
            await issueCredential();
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