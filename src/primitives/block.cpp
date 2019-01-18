// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "crypto/scrypt.h"

#include <time.h>

uint256 CBlockLegacyHeader::GetHash() const
{
    time_t start_time, end_time;
    uint256 ret;

    if (!blockHash.IsNull())
        return blockHash;

    time(&start_time);

    if (nVersion > 6 ) { //&& !IsProofOfWork()) {
        ret = Hash(BEGIN(nVersion), END(nNonce));
    } else {
        ret = GetPoWHash();  
    }

    time(&end_time);

    // LogPrintf("version %d legacy hash %s took %d\n", nVersion, ret.ToString(), end_time - start_time);

    const_cast<CBlockLegacyHeader*>(this)->blockHash = ret;
 
    return ret;
}

uint256 CBlockLegacyHeader::GetPoWHash() const
{
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

uint256 CBlockHeader::GetHash() const
{
    time_t start_time, end_time;
    uint256 ret;

    if (!blockHash.IsNull())
        return blockHash;

    time(&start_time);

    if (nVersion > 6 ) { //&& !IsProofOfWork()) {
        ret = Hash(BEGIN(nVersion), END(nNonce));
    } else {
        ret = GetPoWHash();  
    }

    time(&end_time);

    // LogPrintf("version %d hash %s took %d\n", nVersion, ret.ToString(), end_time - start_time);

    const_cast<CBlockHeader*>(this)->blockHash = ret;

    return ret;
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

std::string CBlockHeader::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlockHeader(ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, blockSig=%s, pos=%s, prevoutStake=%s)\n",
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        HexStr(vchBlockSig),
        IsProofOfStake() ? "PoS" : "PoW",
        prevoutStake.ToString());
    return s.str();
}

CBlock::CBlock(const CBlockLegacy& block)
{
    blockHash      = block.blockHash;
    nVersion       = block.nVersion;
    hashPrevBlock  = block.hashPrevBlock;
    hashMerkleRoot = block.hashMerkleRoot;
    nTime          = block.nTime;
    nBits          = block.nBits;
    nNonce         = block.nNonce;
    vchBlockSig    = block.vchBlockSig;
    vtx            = block.vtx;

    if (block.IsProofOfStake())
        prevoutStake = vtx[1]->vin[0].prevout;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, blockSig=%s, proof=%s, prevoutStake=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        HexStr(vchBlockSig),
        IsProofOfStake() ? "PoS" : "PoW",
        prevoutStake.ToString(),
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

CBlockLegacy::CBlockLegacy(const CBlock &block)
{
    blockHash = block.blockHash;
    nVersion = block.nVersion;
    hashPrevBlock = block.hashPrevBlock;
    hashMerkleRoot = block.hashMerkleRoot;
    nTime = block.nTime;
    nBits = block.nBits;
    nNonce = block.nNonce;
    vtx = block.vtx;
    vchBlockSig = block.vchBlockSig;
}

std::string CBlockLegacy::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlockLegacy(ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, blockSig=%s, proof=%s, vtx=%u)\n",
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        HexStr(vchBlockSig),
        IsProofOfStake() ? "PoS" : "PoW",
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

int64_t GetBlockWeight(const CBlock& block)
{
    // This implements the weight = (stripped_size * 4) + witness_size formula,
    // using only serialization with and without witness data. As witness_size
    // is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}
