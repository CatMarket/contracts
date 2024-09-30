import {
    ByteString,
    PubKey,
    PubKeyHash,
    Sig,
    SmartContract,
    assert,
    hash160,
    method,
    prop,
    sha256,
    FixedArray,
} from 'scrypt-ts'
import { TxUtil, int32 } from '../utils/txUtil'
import {
    PrevoutsCtx,
    SHPreimage,
    SigHashUtils,
    SpentScriptsCtx,
} from '../utils/sigHashUtils'
import { StateUtils, TxoStateHashes } from '../utils/stateUtils'
import { CAT20Proto } from './cat20Proto'

const MAX_OTHER_OUTPUT = 3

export class CAT20SellAll extends SmartContract {
    @prop()
    cat20Script: ByteString

    @prop()
    recvOutput: ByteString

    @prop()
    recvSatoshiBytes: ByteString

    @prop()
    sellerAddress: ByteString

    constructor(
        cat20Script: ByteString,
        recvOutput: ByteString,
        recvSatoshiBytes: ByteString,
        sellerAddress: ByteString
    ) {
        super(...arguments)
        this.cat20Script = cat20Script
        this.recvOutput = recvOutput
        this.recvSatoshiBytes = recvSatoshiBytes
        this.sellerAddress = sellerAddress
    }

    @method()
    public take(
        curTxoStateHashes: TxoStateHashes,
        tokenInputIndex: int32,
        toBuyUserAmount: int32,
        buyUserAddress: PubKeyHash,
        tokenSatoshiBytes: ByteString,
        // sig data
        cancel: boolean,
        pubKeyPrefix: ByteString,
        ownerPubKey: PubKey,
        ownerSig: Sig,
        // ctxs
        shPreimage: SHPreimage,
        prevoutsCtx: PrevoutsCtx,
        spentScriptsCtx: SpentScriptsCtx,
        outputList: FixedArray<ByteString, typeof MAX_OTHER_OUTPUT>,
    ) {
        // check preimage
        if (cancel) {
            assert(hash160(pubKeyPrefix + ownerPubKey) == this.sellerAddress)
            assert(this.checkSig(ownerSig, ownerPubKey))
        } else {
            // Check sighash preimage.
            assert(
                this.checkSig(
                    SigHashUtils.checkSHPreimage(shPreimage),
                    SigHashUtils.Gx
                ),
                'preimage check error'
            )
            // check ctx
            SigHashUtils.checkPrevoutsCtx(
                prevoutsCtx,
                shPreimage.hashPrevouts,
                shPreimage.inputIndex
            )
            SigHashUtils.checkSpentScriptsCtx(
                spentScriptsCtx,
                shPreimage.hashSpentScripts
            )
            // ensure inputs have one token input
            assert(spentScriptsCtx[Number(tokenInputIndex)] == this.cat20Script)
            // build outputs

            // to buyer
            let curStateHashes: ByteString = hash160(
                CAT20Proto.stateHash({
                    amount: toBuyUserAmount,
                    ownerAddr: buyUserAddress,
                })
            )
            const toBuyerTokenOutput = TxUtil.buildOutput(
                this.cat20Script,
                tokenSatoshiBytes
            )

            // satoshi to seller
            const toSellerOutput = TxUtil.buildOutput(
                this.recvOutput,
                this.recvSatoshiBytes
            )

            //
            const curStateCnt: bigint = 1n
            const stateOutput = StateUtils.getCurrentStateOutput(
                curStateHashes,
                curStateCnt,
                curTxoStateHashes
            )
            let outputs = stateOutput + toBuyerTokenOutput + toSellerOutput
            for (let i = 0; i < MAX_OTHER_OUTPUT; i++) {
                outputs += outputList[i]
            }
            const hashOutputs = sha256(outputs)
            assert(
                hashOutputs == shPreimage.hashOutputs,
                'hashOutputs mismatch'
            )
        }
    }
}
