// Copyright (c) 2014 The CLAM developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <vector>
#include <string>
#include <boost/foreach.hpp>

#include "util.h"

extern std::vector<std::string> clamSpeechList;
extern std::vector<std::string> clamSpeech;
extern std::vector<std::string> clamourClamSpeech;
extern std::vector<std::string> quoteList;

class CWeightedSpeech;

extern CWeightedSpeech weightedStakeSpeech;

void CSLoad();

class CWeightedSpeech
{
public:
    typedef std::pair<unsigned long, std::string> pair_t;
    unsigned long nTotal;
    std::vector<pair_t> vSpeech;

    CWeightedSpeech() {
        nTotal = 0;
    }

    void clear() {
        nTotal = 0;
        vSpeech.clear();
    }

    size_t size() {
        return vSpeech.size();
    }

    void insert(unsigned long nWeight, std::string strSpeech) {
        vSpeech.push_back(make_pair(nTotal += nWeight, strSpeech));
    }

    std::string select(unsigned long nRandom) {
        unsigned long  nRemainder = nRandom % nTotal;
        LogPrintf("selecting random speech with nRandom %016x %% %ld = %ld\n", nRandom, nTotal, nRemainder);

        BOOST_FOREACH(const pair_t& pair, vSpeech)
        {
            if (nRemainder < pair.first) {
                LogPrintf("selected random speech: '%s'\n", pair.second);
                return pair.second;
            }
        }

        LogPrintf("this never happens\n");
        return "";
    }
};
