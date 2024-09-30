import {
    ByteString,
    PubKey,
    Sig,
    SmartContract,
    assert,
    hash160,
    method,
    prop,
    sha256,
    toByteString,
    FixedArray
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

export class CAT20BuyAll extends SmartContract {
    @prop()
    cat20Script: ByteString

    @prop()
    toBuyerAmount: int32

    @prop()
    buyerAddress: ByteString

    constructor(
        cat20Script: ByteString,
        toBuyerAmount: int32,
        buyerAddress: ByteString
    ) {
        super(...arguments)
        this.cat20Script = cat20Script
        this.toBuyerAmount = toBuyerAmount
        this.buyerAddress = buyerAddress
    }

    @method()
    public take(
        curTxoStateHashes: TxoStateHashes,
        tokenInputIndex: int32,
        tokenSatoshiBytes: ByteString,
        changeTokenAmount: int32,
        sellerAddress: ByteString,
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
            assert(hash160(pubKeyPrefix + ownerPubKey) == this.buyerAddress)
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
            const buyerTokenStateHash = 
                CAT20Proto.stateHash({
                    amount: this.toBuyerAmount,
                    ownerAddr: this.buyerAddress,
                })
            const toBuyerTokenOutput = TxUtil.buildOutput(
                this.cat20Script,
                tokenSatoshiBytes
            )

            // change token to seller
            let sellerTokenStateHash = toByteString('')
            let toSellerTokenOutput = toByteString('')
            if (changeTokenAmount > 0) {
                sellerTokenStateHash = CAT20Proto.stateHash({
                    amount: changeTokenAmount,
                    ownerAddr: sellerAddress,
                })
                toSellerTokenOutput = TxUtil.buildOutput(
                    this.cat20Script,
                    tokenSatoshiBytes
                )
            }

            // output
            const curStateHashes = hash160(buyerTokenStateHash) + hash160(sellerTokenStateHash)
            const curStateCnt = 2n
            const stateOutput = StateUtils.getCurrentStateOutput(
                curStateHashes,
                curStateCnt,
                curTxoStateHashes
            )

            let outputs = stateOutput + toBuyerTokenOutput + toSellerTokenOutput
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