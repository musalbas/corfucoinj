/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.litecoin;

import com.google.bitcoin.core.*;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptOpCodes;
import com.lambdaworks.crypto.SCrypt;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class LitecoinParams extends NetworkParameters {
    public LitecoinParams() {
        super();
        id = "org.litecoin.production";
        proofOfWorkLimit = Utils.decodeCompactBits(0x1e0fffffL);
        addressHeader = 28;
        acceptableAddressCodes = new int[] { 28 };
        port = 1605;
        packetMagic = 0xfbc0b6dbL;
        dumpedPrivateKeyHeader = 128 + addressHeader;

        targetTimespan = (int)(2.5 * 16  * 60);
        interval = targetTimespan/((int)(2.5 * 60));

        genesisBlock.setDifficultyTarget(0x1e10024c);
        genesisBlock.setTime(1463959997L);
        genesisBlock.setNonce(1397797352);
        genesisBlock.removeTransaction(0);
        Transaction t = new Transaction(this);
        try {
            // A script containing the difficulty bits and the following message:
            //
            //   "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
            byte[] bytes = Hex.decode
                    ("04ffff001d01041c436f7266752c204d6179203330202d204a756e652030322032303136");
            t.addInput(new TransactionInput(this, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode
                    ("4ab2a8b3f5ecc60f08bdebe97235bc3794e5fe6a23d82b4a473664ccc26c892b6e802680baabf2a52753401ed3ce1fffaf1bcdff21dd7d95bae20308c7f35b6102"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(this, t, Utils.toNanoCoins(50, 0), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("2706e9bba710e55833c14b58e4cd9a2c592cfbb8bb1c943e6978281044900dc2"),
                genesisBlock);

        subsidyDecreaseBlockCount = 840000;

        dnsSeeds = new String[] {
                "178.62.58.20","5.135.185.218","104.236.164.80"
        };
    }

    private static BigInteger MAX_MONEY = Utils.COIN.multiply(BigInteger.valueOf(84000000));
    @Override
    public BigInteger getMaxMoney() { return MAX_MONEY; }

    private static LitecoinParams instance;
    public static synchronized LitecoinParams get() {
        if (instance == null) {
            instance = new LitecoinParams();
        }
        return instance;
    }

    /** The number of previous blocks to look at when calculating the next Block's difficulty */
    @Override
    public int getRetargetBlockCount(StoredBlock cursor) {
        if (cursor.getHeight() + 1 != getInterval()) {
            //Logger.getLogger("wallet_ltc").info("Normal LTC retarget");
            return getInterval();
        } else {
            //Logger.getLogger("wallet_ltc").info("Genesis LTC retarget");
            return getInterval() - 1;
        }
    }

    @Override public String getURIScheme() { return "litecoin:"; }

    /** Gets the hash of the given block for the purpose of checking its PoW */
    public Sha256Hash calculateBlockPoWHash(Block b) {
        byte[] blockHeader = b.cloneAsHeader().bitcoinSerialize();
        try {
            return new Sha256Hash(Utils.reverseBytes(SCrypt.scrypt(blockHeader, blockHeader, 1024, 1, 1, 32)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        NetworkParameters.registerParams(get());
        NetworkParameters.PROTOCOL_VERSION = 70002;
    }
}
