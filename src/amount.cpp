// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "consensus/consensus.h"
#include "tinyformat.h"

#include "primitives/transaction.h"
#include <boost/foreach.hpp>

const std::string CURRENCY_UNIT = "CLAM";

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize > 0)
        nSatoshisPerK = nFeePaid * 1000 / nSize;
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nBytes_, unsigned int nBlockSize, bool fRoundUp) const
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    CAmount nBaseFee = 10000;

    unsigned int nNewBlockSize = nBlockSize + nBytes_;
    int64_t nSize = int64_t(nBytes_);
    CAmount nMinFee = (1 + (int64_t)nBytes_ / 1000) * nBaseFee;

    //CAmount nFee = fRoundUp ? (1 + nSize / 1000) * nSatoshisPerK : nSize * nSatoshisPerK / 1000;
    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_BASE_SIZE_GEN / 2) {
        if (nNewBlockSize >= MAX_BLOCK_BASE_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_BASE_SIZE_GEN / (MAX_BLOCK_BASE_SIZE_GEN - nNewBlockSize);
    }
    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%08d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}
