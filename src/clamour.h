// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CCLAMOUR_H
#define BITCOIN_CCLAMOUR_H

#include "uint256.h"
#include "serialize.h"

class CClamour
{
public:
    int nHeight;
    uint256 txid;
    std::string strHash;
    std::string strURL;

    CClamour()
    {
    }

    CClamour(int nHeightIn, uint256 txidIn, std::string& strHashIn, std::string& strURLIn)
    {
        nHeight = nHeightIn;
        txid = txidIn;
        strHash = strHashIn;
        strURL = strURLIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHeight);
        READWRITE(txid);
        READWRITE(strHash);
        READWRITE(strURL);
    }
};

#endif // BITCOIN_CCLAMOUR_TRANSACTION_H