// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    //CBlockIndex will be updated with information about the proof type later
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

inline arith_uint256 GetLimit(const Consensus::Params& params, bool fProofOfStake)
{
    return fProofOfStake ? UintToArith256(params.posLimit) : UintToArith256(params.powLimit);
}


unsigned int CalculateNextWorkRequiredV1(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params, bool fProofOfStake)
{
    int64_t nTargetSpacing = params.nTargetSpacing;
    int64_t nActualSpacing = pindexLast->GetBlockTime() - nFirstBlockTime;

    if (nActualSpacing < 0)
        nActualSpacing = nTargetSpacing;
 
      // Retarget
    const arith_uint256 bnTargetLimit = GetLimit(params, fProofOfStake);

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    int64_t nInterval = params.nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + params.nActualSpacing + params.nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);
 
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;
 
    return bnNew.GetCompact();
 
}
 
unsigned int CalculateNextWorkRequiredV2(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params, bool fProofOfStake)
{
    int64_t nActualSpacing = pindexLast->GetBlockTime() - nFirstBlockTime;
    int64_t nTargetSpacing = params.nTargetSpacing;
    if (nActualSpacing < 0)
        nActualSpacing = currentTargetSpacing;
 
    // Retarget
    const arith_uint256 bnTargetLimit = GetLimit(params, fProofOfStake);

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);
 
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;
 
    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequiredV3(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params, bool fProofOfStake)
{
    // Retarget
    const arith_uint256 bnTargetLimit = GetLimit(params, fProofOfStake);
 
    const CBlockIndex* pindex;
    const CBlockIndex* pindexPrevPrev = NULL;

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block
 
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    int64_t nInterval = (params.nTargetTimespan / params.nTargetStakeSpacing) * 4;
    int64_t count = 0;

    for (pindex = pindexPrev; pindex && pindex->nHeight && count < nInterval; pindex = GetLastBlockIndex(pindex, fProofOfStake))
    {
    pindexPrevPrev = pindex;
        pindex = pindex->pprev;
        if (!pindex) break;
        count++;
        pindex = GetLastBlockIndex(pindex, fProofOfStake);
    }

    if (!pindex || !pindex->nHeight)
        count--;

    count--;

    if (count < 1)
        return bnTargetLimit.GetCompact(); // not enough blocks yet
 
    int64_t nActualSpacing = (pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime()) / count;

    /*
    if (0)
        LogPrintf("nctualSpacing = ((block %d) %"PRId64" - (block %d) %"PRId64") / %"PRId64" = %"PRId64" / %"PRId64" = %"PRId64"\n",
               pindexPrev    ->nHeight, pindexPrev    ->GetBlockTime(),
               pindexPrevPrev->nHeight, pindexPrevPrev->GetBlockTime(),
               count,
               (pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime()), count,
               nActualSpacing);
    */

    if (nActualSpacing < 0) nActualSpacing = params.nTargetStakeSpacing;

    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    bnNew *= ((nInterval - 1) * params.nTargetStakeSpacing + 2 * nActualSpacing);
    bnNew /= ((nInterval + 1) * params.nTargetStakeSpacing);
 
    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;
 
    return bnNew.GetCompact();
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, bool fProofOfStake)
{
    unsigned int  nTargetLimit = GetLimit(params, fProofOfStake).GetCompact();
 
    if (pindexLast == NULL)
        return nTargetLimit; // genesis block
 
    // first block
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return nTargetLimit;

    // second block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return nTargetLimit;

    if (pindexLast->nHeight < params.DISTRIBUTION_END)
        return CalculateNextWorkRequiredV1(pindexPrev, pindexPrevPrev->GetBlockTime(), params, fProofOfStake);
    else if (!IsProtocolV2(pindexLast->nHeight))
        return CalculateNextWorkRequiredV2(pindexPrev, pindexPrevPrev->GetBlockTime(), params, fProofOfStake);
    else    
        return CalculateNextWorkRequiredV3(pindexPrev, pindexPrevPrev->GetBlockTime(), params, fProofOfStake);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, bool fProofOfStake)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > GetLimit(params, fProofOfStake))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
