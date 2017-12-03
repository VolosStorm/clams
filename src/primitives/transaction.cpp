// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::GetWitnessHash() const
{
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), hash(ComputeHash()) {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = (GetTransactionWeight(*this) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, nTime=%d, vin.size=%u, vout.size=%u, nLockTime=%u, clamSpeech=%s)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        nTime, 
        vin.size(),
        vout.size(),
        nLockTime, 
        strCLAMSpeech);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].scriptWitness.ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR -1) + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are 
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.

bool CTransaction::GetCoinAge(CBlockIndex* pindex, const Consensus::Params& consensusParams, uint64_t& nCoinAge) const
{
    CAmount bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        Coin coinPrev;

        if(!view.GetCoin(txin.prevout, coinPrev)){
            return state.DoS(100, error("CheckProofOfStake() : Stake prevout does not exist %s", txin.prevout.hash.ToString()));
        }

        CBlockIndex* blockFrom = pindexPrev->GetAncestor(coinPrev.nHeight);
        if(!blockFrom) {
            return state.DoS(100, error("CheckProofOfStake() : Block at height %i for prevout can not be loaded", coinPrev.nHeight));
        }

        if (nTime < coinPrev.nTime)
            return false;  // Transaction timestamp violation
        if (block.GetBlockTime() + consensusParams.nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        CAmount nValueIn = coinPrev.vout[txin.prevout.n].nValue;
        bnCentSecond +=nValueIn * nTime-txPrev.nTime / 1000000;

        LogPrintf("coinage", "coin age nValueIn=%d nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString());
    }

    CAmount bnCoinDay = bnCentSecond * 1000000 / 100000000 / (24 * 60 * 60);
    LogPrintf("coinage", "coin age bnCoinDay=%s\n", bnCoinDay.ToString());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}



bool CTransaction::IsCreateClamour(string& strHash, string& strURL) const
{
    size_t len = strCLAMSpeech.length();

    if (strCLAMSpeech.substr(0, 15) == "create clamour ")
        LogPrintf("checking speech length %d : %s\n", len, strCLAMSpeech);

    // "create clamour ..." speech must begin with those 15 characters, and have a 64 character hash after it
    if (len < 15+64 || strCLAMSpeech.substr(0, 15) != "create clamour ")
        return false;

    strURL = "";
    strHash = "";

    size_t pos = strCLAMSpeech.find_first_not_of("0123456789abcdef", 15);

    // if the hex goes all the way to the end, there's no URL comment, and the length must be exactly 15+64 or the hex is too long
    if (pos == string::npos) {
        if (len == 15+64) {
            strHash = strCLAMSpeech.substr(15, 64);
            return true;
        }

        return false;
    }

    if (pos != 15+64)
        return false;

    strHash = strCLAMSpeech.substr(15, 64);

    // optional URL is separated from the hash by a single space
    if (strCLAMSpeech[pos] != ' ')
        return true;

    // and ended by whitespace
    size_t pos2 = strCLAMSpeech.find_first_of(" \t\n\r", ++pos);

    strURL = strCLAMSpeech.substr(pos, pos2 == string::npos ? string::npos : pos2 - pos);
    return true;
}
