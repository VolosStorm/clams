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
#include "util.h"

uint256 CBlockHeader::GetHash() const
{
    if (nVersion > 6 ) { //&& !IsProofOfWork()) {
        //LogPrint("xp", "> 6 %s %d %d\n", Hash(BEGIN(nVersion), END(nNonce)).ToString(), nVersion, nNonce);
        return Hash(BEGIN(nVersion), END(nNonce));
    } else {
        //LogPrint("xp", "< 6 %s %d\n", GetPoWHash().ToString(), nVersion);
        return GetPoWHash();  
    }
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}

uint256 CBlockHeader::GetHashWithoutSign() const
{
    return SerializeHash(*this, SER_GETHASH | SER_WITHOUT_SIGNATURE);
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
    this->nVersion       = block.nVersion;
    this->hashPrevBlock  = block.hashPrevBlock;
    this->hashMerkleRoot = block.hashMerkleRoot;
    this->nTime          = block.nTime;
    this->nBits          = block.nBits;
    this->nNonce         = block.nNonce;
    for (unsigned int j = 0; j < block.vchBlockSig.size(); j++)
    {
        this->vchBlockSig[j] = block.vchBlockSig[j];
    }
    this->prevoutStake   = block.vtx[1]->vin[0].prevout;
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        this->vtx[i] = block.vtx[i];
    }
    //vtx            = *block.vtx;
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
