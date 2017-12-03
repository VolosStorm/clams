// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRDB_H
#define BITCOIN_ADDRDB_H

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

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nHeight);
        READWRITE(txid);
        READWRITE(strHash);
        READWRITE(strURL);
    )
};