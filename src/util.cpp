// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "util.h"

#include "chainparamsbase.h"
#include "clamspeech.h"
#include "random.h"
#include "serialize.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <stdarg.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {

    namespace program_options {
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;

const char * const BITCOIN_CONF_FILENAME = "bitcoin.conf";
const char * const BITCOIN_PID_FILENAME = "bitcoind.pid";

CCriticalSection cs_args;
map<string, string> mapArgs;
static map<string, vector<string> > _mapMultiArgs;
const map<string, vector<string> >& mapMultiArgs = _mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
string strDefaultSpeech;
string strDefaultStakeSpeech;

bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
std::atomic<bool> fReopenDebugLog(false);
CTranslationInterface translationInterface;

std::vector<std::string> clamSpeechList;
std::vector<std::string> clamSpeech;
std::vector<std::string> clamourClamSpeech;
std::vector<std::string> quoteList;
CWeightedSpeech weightedStakeSpeech;

/** Init OpenSSL library multithreading support */
static CCriticalSection** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CCriticalSection*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();

#ifdef WIN32
        // Seed OpenSSL PRNG with current contents of the screen
        RAND_screen();
#endif

        // Seed OpenSSL PRNG with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Securely erase the memory used by the PRNG
        RAND_cleanup();
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

/**
 * We use boost::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
static list<string> *vMsgsBeforeOpenLog;

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == NULL);
    mutexDebugLog = new boost::mutex();
    vMsgsBeforeOpenLog = new list<string>;
}

void OpenDebugLog()
{
    boost::call_once(&DebugPrintInit, debugPrintInitFlag);
    boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

    assert(fileout == NULL);
    assert(vMsgsBeforeOpenLog);
    boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) {
        setbuf(fileout, NULL); // unbuffered
        // dump buffered messages from before we opened the log
        while (!vMsgsBeforeOpenLog->empty()) {
            FileWriteStr(vMsgsBeforeOpenLog->front(), fileout);
            vMsgsBeforeOpenLog->pop_front();
        }
    }

    delete vMsgsBeforeOpenLog;
    vMsgsBeforeOpenLog = NULL;
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL)
    {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<set<string> > ptrCategory;
        if (ptrCategory.get() == NULL)
        {
            if (mapMultiArgs.count("-debug")) {
                const vector<string>& categories = mapMultiArgs.at("-debug");
                ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
                // thread_specific_ptr automatically deletes the set when the thread ends.
            } else
                ptrCategory.reset(new set<string>());
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(string("")) == 0 &&
            setCategories.count(string("1")) == 0 &&
            setCategories.count(string(category)) == 0)
            return false;
    }
    return true;
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
static std::string LogTimestampStr(const std::string &str, std::atomic_bool *fStartedNewLine)
{
    string strStamped;

    if (!fLogTimestamps)
        return str;

    if (*fStartedNewLine) {
        int64_t nTimeMicros = GetLogTimeMicros();
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros/1000000);
        if (fLogTimeMicros)
            strStamped += strprintf(".%06d", nTimeMicros%1000000);
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    static std::atomic_bool fStartedNewLine(true);

    string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // buffer if we haven't opened the log yet
        if (fileout == NULL) {
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) {
                fReopenDebugLog = false;
                boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

/** Turn -noX into -X=0 */
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o')
    {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    LOCK(cs_args);
    mapArgs.clear();
    _mapMultiArgs.clear();

    for (int i = 1; i < argc; i++)
    {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos)
        {
            strValue = str.substr(is_index+1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);
        InterpretNegativeSetting(str, strValue);

        mapArgs[str] = strValue;
        _mapMultiArgs[str].push_back(strValue);
    }
}

bool IsArgSet(const std::string& strArg)
{
    LOCK(cs_args);
    return mapArgs.count(strArg);
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return InterpretBool(mapArgs[strArg]);
    return fDefault;
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

void ForceSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    mapArgs[strArg] = strValue;
}



static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

static std::string FormatException(const std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "bitcoin";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintExceptionContinue(const std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
}

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Bitcoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Bitcoin
    // Mac: ~/Library/Application Support/Bitcoin
    // Unix: ~/.bitcoin
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "Bitcoin";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    return pathRet / "Library/Application Support/Bitcoin";
#else
    // Unix
    return pathRet / ".bitcoin";
#endif
#endif
}

static boost::filesystem::path pathCached;
static boost::filesystem::path pathCachedNetSpecific;
static CCriticalSection csPathCached;

const boost::filesystem::path &GetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    if (IsArgSet("-datadir")) {
        path = fs::system_complete(GetArg("-datadir", ""));
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);

    return path;
}

void ClearDatadirCache()
{
    LOCK(csPathCached);

    pathCached = boost::filesystem::path();
    pathCachedNetSpecific = boost::filesystem::path();
}

boost::filesystem::path GetConfigFile(const std::string& confPath)
{
    boost::filesystem::path pathConfigFile(confPath);
    if (!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

void ReadConfigFile(const std::string& confPath)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile(confPath));
    if (!streamConfig.good())
        return; // No bitcoin.conf file is OK

    {
        LOCK(cs_args);
        set<string> setOptions;
        setOptions.insert("*");

        for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
        {
            // Don't overwrite existing settings so command line settings override bitcoin.conf
            string strKey = string("-") + it->string_key;
            string strValue = it->value[0];
            InterpretNegativeSetting(strKey, strValue);
            if (mapArgs.count(strKey) == 0)
                mapArgs[strKey] = strValue;
            _mapMultiArgs[strKey].push_back(strValue);
        }
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}

#ifndef WIN32
boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", BITCOIN_PID_FILENAME));
    if (!pathPidFile.is_complete()) pathPidFile = GetDataDir() / pathPidFile;
    return pathPidFile;
}

void CreatePidFile(const boost::filesystem::path &path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file)
    {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try
    {
        return boost::filesystem::create_directory(p);
    } catch (const boost::filesystem::filesystem_error&) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE *file)
{
    fflush(file); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    FlushFileBuffers(hFile);
#else
    #if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(file));
    #elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(file), F_FULLFSYNC, 0);
    #else
    fsync(fileno(file));
    #endif
#endif
}

bool TruncateFile(FILE *file, unsigned int length) {
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD) {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");
    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes
    if (file && boost::filesystem::file_size(pathLog) > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10))
    {
        // Restart the file with some of the end
        std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(vch.data(), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file)
        {
            fwrite(vch.data(), 1, nBytes, file);
            fclose(file);
        }
    }
    else if (file != NULL)
        fclose(file);
}

#ifdef WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate))
    {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

void runCommand(const std::string& strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

void SetupEnvironment()
{
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // boost::filesystem::path, which is then used to explicitly imbue the path.
    std::locale loc = boost::filesystem::path::imbue(std::locale::classic());
    boost::filesystem::path::imbue(loc);
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

int GetNumCores()
{
#if BOOST_VERSION >= 105600
    return boost::thread::physical_concurrency();
#else // Must fall back to hardware_concurrency, which unfortunately counts virtual cores
    return boost::thread::hardware_concurrency();
#endif
}

std::string CopyrightHolders(const std::string& strPrefix)
{
    std::string strCopyrightHolders = strPrefix + strprintf(_(COPYRIGHT_HOLDERS), _(COPYRIGHT_HOLDERS_SUBSTITUTION));

    // Check for untranslated substitution to make sure Bitcoin Core copyright is not removed by accident
    if (strprintf(COPYRIGHT_HOLDERS, COPYRIGHT_HOLDERS_SUBSTITUTION).find("Bitcoin Core") == std::string::npos) {
        strCopyrightHolders += "\n" + strPrefix + "The Bitcoin Core developers";
    }
    return strCopyrightHolders;
}


static const long hextable[] = 
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 10-19
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 30-39
    -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,
     2,  3,  4,  5,  6,  7,  8,  9, -1, -1,     // 50-59
    -1, -1, -1, -1, -1, 10, 11, 12, 13, 14,
    15, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 70-79
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 10, 11, 12,     // 90-99
    13, 14, 15, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 110-109
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 130-139
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 150-159
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 170-179
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 190-199
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 210-219
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,     // 230-239
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1
};



long hex2long(const char* hexString)
{
    long ret = 0; 

    while (*hexString && ret >= 0) 
    {
        ret = (ret << 4) | hextable[int(*hexString++)];
    }

    return ret; 
}

void CSLoad() {
    const char *texts[] = {
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks. -Satoshi Nakamoto",
        "If you don’t believe me or don’t get it, I don’t have time to try to convince you, sorry. -Satoshi Nakamoto",
        "Institutional momentum is to stick with the last decision. -Satoshi Nakamoto",
        "WikiLeaks has kicked the hornet’s nest, and the swarm is headed towards us. -Satoshi Nakamoto",
        "I am not Dorian Nakamoto. -Satoshi Nakamoto",
        "It is regulated by algorithm instead of being regulated by government bureaucracies. Un-corrupted. -Andreas Antonopolous",
        "...if a government bans bitcoin it will instantly be more credible as an alternative choice. -Andreas Antonopolous",
        "Bitcoin will survive the banking regulators and oppressive governments. The converse however is unlikely. -Andreas Antonopolous",
        "Countries rejecting bitcoin reminds me of the time when countries were resisting the Internet. -Andreas Antonopolous",
        "Most people are yet to understand how disruptive the Bitcoin technology really is. -Andreas Antonopolous",
        "Bitcoin’s success is owed to creativity and innovation. It has nothing to do with the government’s endorsement -Andreas Antonopolous",
        "Bitcoin is global, decentralized and unstoppable. Let government try, it will be hilarious to watch. -Andreas Antonopolous",
        "When the regulators come to regulate Bitcoin for your own good, your reply should be ‘Fuck Off! -Andreas Antonopolous",
        "Expression of Religious Freedom: The Great CLAM",
        "Expression of Religious Freedom: Atheism",
        "Expression of Religious Freedom: Agnosticism",
        "Expression of Religious Freedom: Bábism",
        "Expression of Religious Freedom: Bahá'í Faith",
        "Expression of Religious Freedom: Christianity",
        "Expression of Religious Freedom: Mormonism",
        "Expression of Religious Freedom: Gnosticism",
        "Expression of Religious Freedom: Islam",
        "Expression of Religious Freedom: Druze",
        "Expression of Religious Freedom: Judaism",
        "Expression of Religious Freedom: Black Hebrew Israelites",
        "Expression of Religious Freedom: Rastafari",
        "Expression of Religious Freedom: Mandaeism",
        "Expression of Religious Freedom: Sabianism",
        "Expression of Religious Freedom: Shabakism",
        "Expression of Religious Freedom: Ayyavazhi",
        "Expression of Religious Freedom: Bhakti",
        "Expression of Religious Freedom: Buddhism",
        "Expression of Religious Freedom: Din-e Ilahi",
        "Expression of Religious Freedom: Hinduism",
        "Expression of Religious Freedom: Jainism",
        "Expression of Religious Freedom: Meivazhi",
        "Expression of Religious Freedom: Sikhism",
        "Expression of Religious Freedom: Zoroastrianism",
        "Expression of Religious Freedom: Gnosticism",
        "Expression of Religious Freedom: Bábí",
        "Expression of Religious Freedom: Yazdânism",
        "Expression of Religious Freedom: Confucianism",
        "Expression of Religious Freedom: Shinto",
        "Expression of Religious Freedom: Taoism",
        "Expression of Religious Freedom: Chan Buddhism",
        "Expression of Religious Freedom: Chinese Folk",
        "Expression of Religious Freedom: Falun Gong",
        "Expression of Religious Freedom: Yiguandao",
        "Expression of Religious Freedom: Mohism",
        "Expression of Religious Freedom: Xiantiandao",
        "Expression of Religious Freedom: Cheondoism",
        "Expression of Religious Freedom: Daejongism",
        "Expression of Religious Freedom: Daesun Jinrihoe",
        "Expression of Religious Freedom: Gasin",
        "Expression of Religious Freedom: Jeung San Do",
        "Expression of Religious Freedom: Juche",
        "Expression of Religious Freedom: Korean Shamanism",
        "Expression of Religious Freedom: Suwunism",
        "Expression of Religious Freedom: Batuque",
        "Expression of Religious Freedom: Candomblé",
        "Expression of Religious Freedom: Dahomey Mythology",
        "Expression of Religious Freedom: Haitian Mythology",
        "Expression of Religious Freedom: Kumina",
        "Expression of Religious Freedom: Macumba",
        "Expression of Religious Freedom: Mami Wata",
        "Expression of Religious Freedom: Obeah",
        "Expression of Religious Freedom: Oyotunji",
        "Expression of Religious Freedom: Palo",
        "Expression of Religious Freedom: Quimbanda",
        "Expression of Religious Freedom: Santería",
        "Expression of Religious Freedom: Umbanda",
        "Expression of Religious Freedom: Vodou",
        "Expression of Religious Freedom: Akan Mythology",
        "Expression of Religious Freedom: Ashanti Mythology",
        "Expression of Religious Freedom: Dahomey Mythology",
        "Expression of Religious Freedom: Efik Mythology",
        "Expression of Religious Freedom: Igbo Mythology",
        "Expression of Religious Freedom: Isoko Mythology",
        "Expression of Religious Freedom: Yoruba Mythology",
        "Expression of Religious Freedom: Bushongo Mythology",
        "Expression of Religious Freedom: Bambuti Mythology",
        "Expression of Religious Freedom: Lugbara Mythology",
        "Expression of Religious Freedom: Akamba Mythology",
        "Expression of Religious Freedom: Dinka Mythology",
        "Expression of Religious Freedom: Lotuko Mythology",
        "Expression of Religious Freedom: Masai Mythology",
        "Expression of Religious Freedom: Khoisan",
        "Expression of Religious Freedom: Lozi Mythology",
        "Expression of Religious Freedom: Tumbuka Mythology",
        "Expression of Religious Freedom: Zulu Mythology",
        "Expression of Religious Freedom: Abenaki Mythology",
        "Expression of Religious Freedom: Anishinaabe",
        "Expression of Religious Freedom: Aztec Mythology",
        "Expression of Religious Freedom: Blackfoot Mythology",
        "Expression of Religious Freedom: Cherokee Mythology",
        "Expression of Religious Freedom: Chickasaw Mythology",
        "Expression of Religious Freedom: Choctaw Mythology",
        "Expression of Religious Freedom: Creek Mythology",
        "Expression of Religious Freedom: Crow Mythology",
        "Expression of Religious Freedom: Ghost Dance",
        "Expression of Religious Freedom: Guarani Mythology",
        "Expression of Religious Freedom: Haida Mythology",
        "Expression of Religious Freedom: Ho-Chunk Mythology",
        "Expression of Religious Freedom: Hopi Mythology",
        "Expression of Religious Freedom: Inca Mythology",
        "Expression of Religious Freedom: Indian Shaker",
        "Expression of Religious Freedom: Inuit Mythology",
        "Expression of Religious Freedom: Iroquois Mythology",
        "Expression of Religious Freedom: Keetoowah Nighthawk",
        "Expression of Religious Freedom: Kuksu",
        "Expression of Religious Freedom: Kwakiutl Mythology",
        "Expression of Religious Freedom: Lakota Mythology",
        "Expression of Religious Freedom: Leni Lenape Mythology",
        "Expression of Religious Freedom: Longhouse",
        "Expression of Religious Freedom: Mapuche Mythology",
        "Expression of Religious Freedom: Maya Mythology",
        "Expression of Religious Freedom: Midewiwin",
        "Expression of Religious Freedom: Miwok",
        "Expression of Religious Freedom: Native American",
        "Expression of Religious Freedom: Navajo Mythology",
        "Expression of Religious Freedom: Nootka Mythology",
        "Expression of Religious Freedom: Ohlone Mythology",
        "Expression of Religious Freedom: Olmec Mythology",
        "Expression of Religious Freedom: Pomo Mythology",
        "Expression of Religious Freedom: Pawnee Mythology",
        "Expression of Religious Freedom: Salish Mythology",
        "Expression of Religious Freedom: Selk'nam",
        "Expression of Religious Freedom: Seneca Mythology",
        "Expression of Religious Freedom: Southeastern Ceremonial",
        "Expression of Religious Freedom: Sun Dance",
        "Expression of Religious Freedom: Tsimshian Mythology",
        "Expression of Religious Freedom: Urarina",
        "Expression of Religious Freedom: Ute Mythology",
        "Expression of Religious Freedom: Wyandot",
        "Expression of Religious Freedom: Zuni Mythology",
        "Expression of Religious Freedom: Benzhuism",
        "Expression of Religious Freedom: Bimoism",
        "Expression of Religious Freedom: Bon",
        "Expression of Religious Freedom: Chinese Mythology",
        "Expression of Religious Freedom: Japanese Mythology",
        "Expression of Religious Freedom: Korean Shamanism",
        "Expression of Religious Freedom: Koshinto",
        "Expression of Religious Freedom: Manchu Shamanism",
        "Expression of Religious Freedom: Mun",
        "Expression of Religious Freedom: Siberian Shamanism",
        "Expression of Religious Freedom: Tengrism",
        "Expression of Religious Freedom: Ua Dab",
        "Expression of Religious Freedom: Vietnamese Folk",
        "Expression of Religious Freedom: Asatru",
        "Expression of Religious Freedom: Estonian Mythology",
        "Expression of Religious Freedom: Eskimo",
        "Expression of Religious Freedom: Finnish Mythology",
        "Expression of Religious Freedom: Finnish Paganism",
        "Expression of Religious Freedom: Marla",
        "Expression of Religious Freedom: Odinism",
        "Expression of Religious Freedom: Romuva",
        "Expression of Religious Freedom: Hungarian Folk",
        "Expression of Religious Freedom: Sami",
        "Expression of Religious Freedom: Wotanism",
        "Expression of Religious Freedom: Australian Aboriginal Mythology",
        "Expression of Religious Freedom: Balinese Mythology",
        "Expression of Religious Freedom: Javanese",
        "Expression of Religious Freedom: Melanesian Mythology",
        "Expression of Religious Freedom: Micronesian Mythology",
        "Expression of Religious Freedom: Modekngei",
        "Expression of Religious Freedom: Nauruan",
        "Expression of Religious Freedom: Philippine Mythology",
        "Expression of Religious Freedom: Anito",
        "Expression of Religious Freedom: Gabâ",
        "Expression of Religious Freedom: Kulam",
        "Expression of Religious Freedom: Polynesian Mythology",
        "Expression of Religious Freedom: Hawaiian Mythology",
        "Expression of Religious Freedom: Maori Mythology",
        "Expression of Religious Freedom: Rapa Nui Mythology",
        "Expression of Religious Freedom: Moai",
        "Expression of Religious Freedom: Tangata Manu",
        "Expression of Religious Freedom: John Frum",
        "Expression of Religious Freedom: Johnson Cult",
        "Expression of Religious Freedom: Prince Philip Movement",
        "Expression of Religious Freedom: Vailala Madness",
        "Expression of Religious Freedom: Ancient Egyptian",
        "Expression of Religious Freedom: Ancient Semitic",
        "Expression of Religious Freedom: Canaanite Mythology",
        "Expression of Religious Freedom: Mesopotamian Mythology",
        "Expression of Religious Freedom: Arabian Mythology",
        "Expression of Religious Freedom: Assyrian Mythology",
        "Expression of Religious Freedom: Babylonian Mythology",
        "Expression of Religious Freedom: Chaldean Mythology",
        "Expression of Religious Freedom: Sumerian Mythology",
        "Expression of Religious Freedom: Proto-Indo-Iranian",
        "Expression of Religious Freedom: Historical Vedic",
        "Expression of Religious Freedom: Iranian Mythology",
        "Expression of Religious Freedom: Armenian Mythology",
        "Expression of Religious Freedom: Baltic Polytheism",
        "Expression of Religious Freedom: Celtic Polytheism",
        "Expression of Religious Freedom: Brythonic Mythology",
        "Expression of Religious Freedom: Gaelic Mythology",
        "Expression of Religious Freedom: Germanic Polytheism",
        "Expression of Religious Freedom: Anglo-Saxon",
        "Expression of Religious Freedom: Continental Germanic",
        "Expression of Religious Freedom: Norse",
        "Expression of Religious Freedom: Greek Polytheism",
        "Expression of Religious Freedom: Hittite Mythology",
        "Expression of Religious Freedom: Persian Mythology",
        "Expression of Religious Freedom: Roman Polytheism",
        "Expression of Religious Freedom: Slavic Polytheism",
        "Expression of Religious Freedom: Eleusinian Mysteries",
        "Expression of Religious Freedom: Mithraism",
        "Expression of Religious Freedom: Orphism",
        "Expression of Religious Freedom: Pythagoreanism",
        "Expression of Religious Freedom: Gallo-Roman",
        "Expression of Religious Freedom: Estonian Polytheism",
        "Expression of Religious Freedom: Finnish Polytheism",
        "Expression of Religious Freedom: Hungarian Polytheism",
        "Expression of Religious Freedom: Hindu Mysticism",
        "Expression of Religious Freedom: Tantra",
        "Expression of Religious Freedom: Vaastu Shastra",
        "Expression of Religious Freedom: Moorish Science",
        "Expression of Religious Freedom: Moorish Orthodox",
        "Expression of Religious Freedom: Neoplatonism",
        "Expression of Religious Freedom: Pythagoreanism",
        "Expression of Religious Freedom: Neopythagoreanism",
        "Expression of Religious Freedom: Theosophy",
        "Expression of Religious Freedom: Sufism",
        "Expression of Religious Freedom: Hermeticism",
        "Expression of Religious Freedom: Builders of the Adytum",
        "Expression of Religious Freedom: Fraternitas Saturni",
        "Expression of Religious Freedom: Fraternity of the Inner Light",
        "Expression of Religious Freedom: Hermetic Order of the Golden Dawn",
        "Expression of Religious Freedom: The Open Source Order of the Golden Dawn",
        "Expression of Religious Freedom: Ordo Aurum Solis",
        "Expression of Religious Freedom: Rosicrucian",
        "Expression of Religious Freedom: Servants of the Light",
        "Expression of Religious Freedom: Ordo Templi Orientis",
        "Expression of Religious Freedom: Ecclesia Gnostica Catholica",
        "Expression of Religious Freedom: Typhonian Order",
        "Expression of Religious Freedom: Anthroposophy",
        "Expression of Religious Freedom: Behmenism",
        "Expression of Religious Freedom: Christian Kabbalah",
        "Expression of Religious Freedom: Martinism",
        "Expression of Religious Freedom: Ceremonial Magic",
        "Expression of Religious Freedom: Enochian Magic",
        "Expression of Religious Freedom: Goetic Magic",
        "Expression of Religious Freedom: Chaos Magic",
        "Expression of Religious Freedom: Illuminates of Thanateros",
        "Expression of Religious Freedom: Thee Temple ov Psychick Youth",
        "Expression of Religious Freedom: Hoodoo",
        "Expression of Religious Freedom: New Orleans Voodoo",
        "Expression of Religious Freedom: Kulam",
        "Expression of Religious Freedom: Pow-Wow",
        "Expression of Religious Freedom: Seiðr",
        "Expression of Religious Freedom: Magick",
        "Expression of Religious Freedom: Witchcraft",
        "Expression of Religious Freedom: Adonism",
        "Expression of Religious Freedom: Church of All Worlds",
        "Expression of Religious Freedom: Church of Aphrodite",
        "Expression of Religious Freedom: Feraferia",
        "Expression of Religious Freedom: Neo-Druidism",
        "Expression of Religious Freedom: Reformed Druids",
        "Expression of Religious Freedom: Neoshamanism",
        "Expression of Religious Freedom: Neo-völkisch",
        "Expression of Religious Freedom: Technopaganism",
        "Expression of Religious Freedom: Wicca",
        "Expression of Religious Freedom: British Traditional Wicca",
        "Expression of Religious Freedom: Gardnerian Wicca",
        "Expression of Religious Freedom: Alexandrian Wicca",
        "Expression of Religious Freedom: Central Valley Wicca",
        "Expression of Religious Freedom: Algard Wicca",
        "Expression of Religious Freedom: Chthonioi Alexandrian Wicca",
        "Expression of Religious Freedom: Blue Star Wicca",
        "Expression of Religious Freedom: Eclectic Wicca",
        "Expression of Religious Freedom: Celtic Wicca",
        "Expression of Religious Freedom: Saxon Wicca",
        "Expression of Religious Freedom: Dianic Wicca",
        "Expression of Religious Freedom: McFarland Dianic Wicca",
        "Expression of Religious Freedom: Faery Wicca",
        "Expression of Religious Freedom: Correllian Nativist",
        "Expression of Religious Freedom: Georgian Wicca",
        "Expression of Religious Freedom: Odyssean Wicca",
        "Expression of Religious Freedom: Covenant of the Goddess",
        "Expression of Religious Freedom: Baltic Neopaganism",
        "Expression of Religious Freedom: Celtic Neopaganism",
        "Expression of Religious Freedom: Finnish Neopaganism",
        "Expression of Religious Freedom: Germanic Neopaganism",
        "Expression of Religious Freedom: Hellenismos",
        "Expression of Religious Freedom: Kemetism",
        "Expression of Religious Freedom: Roman Neopaganism",
        "Expression of Religious Freedom: Semitic Neopaganism",
        "Expression of Religious Freedom: Slavic Neopaganism",
        "Expression of Religious Freedom: Taaraism",
        "Expression of Religious Freedom: Zalmoxianism",
        "Expression of Religious Freedom: Creativity",
        "Expression of Religious Freedom: Huna",
        "Expression of Religious Freedom: Raëlism",
        "Expression of Religious Freedom: Scientology",
        "Expression of Religious Freedom: Unitarian Universalist",
        "Expression of Religious Freedom: Christian Science",
        "Expression of Religious Freedom: Church Universal and Triumphant",
        "Expression of Religious Freedom: Divine Science",
        "Expression of Religious Freedom: Religious Science",
        "Expression of Religious Freedom: Unity Church",
        "Expression of Religious Freedom: Jewish Science",
        "Expression of Religious Freedom: Seicho-no-Ie",
        "Expression of Religious Freedom: Church of World Messianity",
        "Expression of Religious Freedom: Happy Science",
        "Expression of Religious Freedom: Konkokyo",
        "Expression of Religious Freedom: Oomoto",
        "Expression of Religious Freedom: PL Kyodan",
        "Expression of Religious Freedom: Seicho-No-Ie",
        "Expression of Religious Freedom: Tenrikyo",
        "Expression of Religious Freedom: Satanism",
        "Expression of Religious Freedom: LaVeyan Satanism",
        "Expression of Religious Freedom: Theistic Satanism",
        "Expression of Religious Freedom: Our Lady of Endor Coven",
        "Expression of Religious Freedom: Demonolatry",
        "Expression of Religious Freedom: Luciferianism",
        "Expression of Religious Freedom: Setianism",
        "Expression of Religious Freedom: Discordianism",
        "Expression of Religious Freedom: Ethical Culture",
        "Expression of Religious Freedom: Freethought",
        "Expression of Religious Freedom: Jesusism",
        "Expression of Religious Freedom: Naturalistic Pantheism",
        "Expression of Religious Freedom: Secular Humanism",
        "Expression of Religious Freedom: Yoism",
        "Expression of Religious Freedom: Church of Euthanasia",
        "Expression of Religious Freedom: Pastafarianism",
        "Expression of Religious Freedom: Church of the SubGenius",
        "Expression of Religious Freedom: Dudeism",
        "Expression of Religious Freedom: Iglesia Maradoniana",
        "Expression of Religious Freedom: Invisible Pink Unicorn",
        "Expression of Religious Freedom: Jediism",
        "Expression of Religious Freedom: Kibology",
        "Expression of Religious Freedom: Landover Baptist",
        "Expression of Religious Freedom: Last Thursdayism",
        "Expression of Religious Freedom: Cult of the Supreme Being",
        "Expression of Religious Freedom: Deism",
        "Expression of Religious Freedom: Eckankar",
        "Expression of Religious Freedom: Fourth Way",
        "Expression of Religious Freedom: Goddess Movement",
        "Expression of Religious Freedom: Humanism",
        "Expression of Religious Freedom: The New Message from God",
        "Expression of Religious Freedom: Nuwaubian Nation",
        "Expression of Religious Freedom: Open-source",
        "Expression of Religious Freedom: Plurationalism",
        "Expression of Religious Freedom: Spiritism",
        "Expression of Religious Freedom: Subud",
        "Expression of Religious Freedom: Universal Life",
        "Expression of Political Freedom: Libertarianism",
        "Expression of Political Freedom: Far-left",
        "Expression of Political Freedom: Left-wing",
        "Expression of Political Freedom: Center-left",
        "Expression of Political Freedom: Center",
        "Expression of Political Freedom: Center-right",
        "Expression of Political Freedom: Right-wing",
        "Expression of Political Freedom: Far-right",
        "Expression of Political Freedom: Radical left",
        "Expression of Political Freedom: Radical center",
        "Expression of Political Freedom: Radical right",
        "Expression of Political Freedom: Radicalism",
        "Expression of Political Freedom: Liberalism",
        "Expression of Political Freedom: Moderate",
        "Expression of Political Freedom: Conservatism",
        "Expression of Political Freedom: Reactionism",
        "Expression of Political Freedom: Libertarianism",
        "Expression of Political Freedom: Syncretic",
        "Expression of Political Freedom: Extremism",
        "Expression of Political Freedom: Partisan",
        "Expression of Political Freedom: Fundamentalism",
        "Expression of Political Freedom: Fanaticism",
        "Expression of Political Freedom: Dominant-party",
        "Expression of Political Freedom: Non-partisan",
        "Expression of Political Freedom: Single-party",
        "Expression of Political Freedom: Two-party",
        "Expression of Political Freedom: Multi-party",
        "Expression of Political Freedom: Minority Government",
        "Expression of Political Freedom: Confidence & Supply",
        "Expression of Political Freedom: Rainbow Coalition",
        "Expression of Political Freedom: Full Coalition",
        "Expression of Political Freedom: Majority Government",
        "Expression of Political Freedom: Grand Coalition",
        "Expression of Political Freedom: National Unity Government",
        "Expression of Political Freedom: Confederation",
        "Expression of Political Freedom: Federation",
        "Expression of Political Freedom: Hegemony",
        "Expression of Political Freedom: Empire",
        "Expression of Political Freedom: Unitary state",
        "Expression of Political Freedom: Autocracy",
        "Expression of Political Freedom: Despotism",
        "Expression of Political Freedom: Dictatorship",
        "Expression of Political Freedom: Totalitarianism",
        "Expression of Political Freedom: Direct Democracy",
        "Expression of Political Freedom: Representative Democracy",
        "Expression of Political Freedom: Absolute Monarchy",
        "Expression of Political Freedom: Constitutional Monarchy",
        "Expression of Political Freedom: Aristocracy",
        "Expression of Political Freedom: Military junta",
        "Expression of Political Freedom: Plutocracy",
        "Expression of Political Freedom: Stratocracy",
        "Expression of Political Freedom: Timocracy",
        "Expression of Political Freedom: Anarchy",
        "Expression of Political Freedom: Anocracy",
        "Expression of Political Freedom: Kritarchy",
        "Expression of Political Freedom: Particracy",
        "Expression of Political Freedom: Republic",
        "Expression of Political Freedom: Theocracy",
        "Expression of Political Freedom: Anarchism",
        "Expression of Political Freedom: Anarchism without adjectives",
        "Expression of Political Freedom: Individualist anarchism",
        "Expression of Political Freedom: Religious anarchism",
        "Expression of Political Freedom: Social anarchism",
        "Expression of Political Freedom: Anarchist communism",
        "Expression of Political Freedom: Communism",
        "Expression of Political Freedom: Marxism",
        "Expression of Political Freedom: Revisionism",
        "Expression of Political Freedom: Leninism",
        "Expression of Political Freedom: Anti-revisionism",
        "Expression of Political Freedom: Conservatism",
        "Expression of Political Freedom: Environmentalism",
        "Expression of Political Freedom: Gender equality",
        "Expression of Political Freedom: Feminism",
        "Expression of Political Freedom: Religious feminism",
        "Expression of Political Freedom: LGBT",
        "Expression of Political Freedom: Masculism",
        "Expression of Political Freedom: Libertarianism",
        "Expression of Political Freedom: Libertarian socialism",
        "Expression of Political Freedom: Right libertarianism",
        "Expression of Political Freedom: Fascism",
        "Expression of Political Freedom: Zionism",
        "Expression of Political Freedom: Unification movements",
        "Expression of Political Freedom: Buddhism",
        "Expression of Political Freedom: Christianity",
        "Expression of Political Freedom: Hinduism",
        "Expression of Political Freedom: Islam",
        "Expression of Political Freedom: Judaism",
        "Expression of Political Freedom: Mormonism",
        "Expression of Political Freedom: Sikhism",
        "Expression of Political Freedom: Socialism",
        "Expression of Political Freedom: Libertarian Marxism",
        "Expression of Political Freedom: Reformist socialism",
        "Expression of Political Freedom: Democratic socialism",
        "Expression of Political Freedom: Social democracy",
        "Expression of Political Freedom: Religious socialism",
        "Expression of Political Freedom: Revolutionary socialism",
        "Expression of Political Freedom: Synthesis anarchism",
        "Expression of Political Freedom: Anarchist naturism",
        "Expression of Political Freedom: Egoist anarchism",
        "Expression of Political Freedom: Freiwirtschaft",
        "Expression of Political Freedom: Geoanarchism",
        "Expression of Political Freedom: Inclusive Democracy",
        "Expression of Political Freedom: Individualist anarchism",
        "Expression of Political Freedom: Insurrectionary anarchism",
        "Expression of Political Freedom: Illegalism",
        "Expression of Political Freedom: Mutualism",
        "Expression of Political Freedom: Buddhist anarchism",
        "Expression of Political Freedom: Christian anarchism",
        "Expression of Political Freedom: Islamic anarchism",
        "Expression of Political Freedom: Jewish anarchism",
        "Expression of Political Freedom: Anarcha-feminism",
        "Expression of Political Freedom: Anarcho-syndicalism",
        "Expression of Political Freedom: Collectivist anarchism",
        "Expression of Political Freedom: Participatory economics",
        "Expression of Political Freedom: Social anarchism",
        "Expression of Political Freedom: Social ecology",
        "Expression of Political Freedom: Magonism",
        "Expression of Political Freedom: Platformism",
        "Expression of Political Freedom: Autarchism",
        "Expression of Political Freedom: Autonomism",
        "Expression of Political Freedom: Crypto-anarchism",
        "Expression of Political Freedom: Indigenism",
        "Expression of Political Freedom: Infoanarchism",
        "Expression of Political Freedom: Makhnovism",
        "Expression of Political Freedom: National-Anarchism",
        "Expression of Political Freedom: Panarchism",
        "Expression of Political Freedom: Platformism",
        "Expression of Political Freedom: Post-anarchism",
        "Expression of Political Freedom: Post-left anarchy",
        "Expression of Political Freedom: Queer anarchism",
        "Expression of Political Freedom: Workerism",
        "Expression of Political Freedom: Pluralism",
        "Expression of Political Freedom: Stateless communism",
        "Expression of Political Freedom: Revolutionary socialism",
        "Expression of Political Freedom: Neo-Marxism",
        "Expression of Political Freedom: Classical Marxism",
        "Expression of Political Freedom: Autonomism",
        "Expression of Political Freedom: Luxemburgism",
        "Expression of Political Freedom: Left communism",
        "Expression of Political Freedom: Communization",
        "Expression of Political Freedom: Council communism",
        "Expression of Political Freedom: Titoism",
        "Expression of Political Freedom: Castroism",
        "Expression of Political Freedom: Religious communism",
        "Expression of Political Freedom: Christian communism",
        "Expression of Political Freedom: Anarchist communism",
        "Expression of Political Freedom: Platformism",
        "Expression of Political Freedom: Eurocommunism",
        "Expression of Political Freedom: Orthodox Marxism",
        "Expression of Political Freedom: Leninism",
        "Expression of Political Freedom: Marxism–Leninism",
        "Expression of Political Freedom: Guevarism",
        "Expression of Political Freedom: World communism",
        "Expression of Political Freedom: Primitive communism",
        "Expression of Political Freedom: Scientific communism",
        "Expression of Political Freedom: Stalinism",
        "Expression of Political Freedom: Maoism",
        "Expression of Political Freedom: Ho Chi Minh Thought",
        "Expression of Political Freedom: Hoxhaism",
        "Expression of Political Freedom: Conservative liberalism",
        "Expression of Political Freedom: Cultural conservatism",
        "Expression of Political Freedom: Liberal conservatism",
        "Expression of Political Freedom: Libertarian conservatism",
        "Expression of Political Freedom: National conservatism",
        "Expression of Political Freedom: Neoconservatism",
        "Expression of Political Freedom: Paleoconservatism",
        "Expression of Political Freedom: Social conservatism",
        "Expression of Political Freedom: Agrarianism",
        "Expression of Political Freedom: Bioconservatism",
        "Expression of Political Freedom: Black conservatism",
        "Expression of Political Freedom: Carlism",
        "Expression of Political Freedom: Civic Conservatism",
        "Expression of Political Freedom: Christian democracy",
        "Expression of Political Freedom: Communitarianism",
        "Expression of Political Freedom: Fiscal conservatism",
        "Expression of Political Freedom: Green conservatism",
        "Expression of Political Freedom: Latin Conservatism",
        "Expression of Political Freedom: Monarchism",
        "Expression of Political Freedom: Right-libertarianism",
        "Expression of Political Freedom: Roman Catholic conservatism",
        "Expression of Political Freedom: Theoconservatism",
        "Expression of Political Freedom: Toryism",
        "Expression of Political Freedom: Traditionalist conservatism",
        "Expression of Political Freedom: Reactionary",
        "Expression of Political Freedom: Anarchist naturism",
        "Expression of Political Freedom: Anarcho-primitivism",
        "Expression of Political Freedom: Bioregionalism",
        "Expression of Political Freedom: Bright green environmentalism",
        "Expression of Political Freedom: Deep ecology",
        "Expression of Political Freedom: Eco-capitalism",
        "Expression of Political Freedom: Ecofascism",
        "Expression of Political Freedom: Ecofeminism",
        "Expression of Political Freedom: Eco-socialism",
        "Expression of Political Freedom: Environmentalism",
        "Expression of Political Freedom: Free-market environmentalism",
        "Expression of Political Freedom: Green anarchism",
        "Expression of Political Freedom: Green conservatism",
        "Expression of Political Freedom: Green liberalism",
        "Expression of Political Freedom: Green libertarianism",
        "Expression of Political Freedom: Green politics",
        "Expression of Political Freedom: Green municipalism",
        "Expression of Political Freedom: Green syndicalism",
        "Expression of Political Freedom: Social ecology",
        "Expression of Political Freedom: Cultural feminism",
        "Expression of Political Freedom: Ecofeminism",
        "Expression of Political Freedom: Feminism",
        "Expression of Political Freedom: Individualist feminism",
        "Expression of Political Freedom: Lesbian feminism",
        "Expression of Political Freedom: Liberal feminism",
        "Expression of Political Freedom: Marxist feminism",
        "Expression of Political Freedom: Masculism",
        "Expression of Political Freedom: Postmodern feminism",
        "Expression of Political Freedom: Psychoanalytic feminism",
        "Expression of Political Freedom: Radical feminism",
        "Expression of Political Freedom: Separatist feminism",
        "Expression of Political Freedom: Socialist feminism",
        "Expression of Political Freedom: Womanism",
        "Expression of Political Freedom: Religious feminism",
        "Expression of Political Freedom: Christian feminism",
        "Expression of Political Freedom: Islamic feminism",
        "Expression of Political Freedom: Jewish feminism",
        "Expression of Political Freedom: LGBT social movements",
        "Expression of Political Freedom: Classical liberalism",
        "Expression of Political Freedom: Conservative liberalism",
        "Expression of Political Freedom: Economic liberalism",
        "Expression of Political Freedom: Individualism",
        "Expression of Political Freedom: Liberal feminism",
        "Expression of Political Freedom: Liberal socialism",
        "Expression of Political Freedom: Liberalism",
        "Expression of Political Freedom: Market liberalism",
        "Expression of Political Freedom: National liberalism",
        "Expression of Political Freedom: Neoliberalism",
        "Expression of Political Freedom: Ordoliberalism",
        "Expression of Political Freedom: Paleoliberalism",
        "Expression of Political Freedom: Social liberalism",
        "Expression of Political Freedom: Colonial liberalism",
        "Expression of Political Freedom: Fourierism",
        "Expression of Political Freedom: Collectivist anarchism",
        "Expression of Political Freedom: Anarcho-communism",
        "Expression of Political Freedom: Anarcho-syndicalism",
        "Expression of Political Freedom: Guild socialism",
        "Expression of Political Freedom: Revolutionary syndicalism",
        "Expression of Political Freedom: Libertarian Marxism",
        "Expression of Political Freedom: Libertarian socialism",
        "Expression of Political Freedom: Left communism",
        "Expression of Political Freedom: Council communism",
        "Expression of Political Freedom: Platformism",
        "Expression of Political Freedom: Gandhian economics",
        "Expression of Political Freedom: Situationist International",
        "Expression of Political Freedom: Autonomism",
        "Expression of Political Freedom: Social ecology",
        "Expression of Political Freedom: Participism",
        "Expression of Political Freedom: Inclusive Democracy",
        "Expression of Political Freedom: Zapatismo",
        "Expression of Political Freedom: Insurrectionary anarchism",
        "Expression of Political Freedom: Communalism",
        "Expression of Political Freedom: Communization",
        "Expression of Political Freedom: Anarcho-capitalism",
        "Expression of Political Freedom: Classical liberalism",
        "Expression of Political Freedom: Libertarian conservatism",
        "Expression of Political Freedom: Minarchism",
        "Expression of Political Freedom: Objectivism",
        "Expression of Political Freedom: Paleolibertarianism",
        "Expression of Political Freedom: Right libertarianism",
        "Expression of Political Freedom: Voluntaryism",
        "Expression of Political Freedom: Agorism",
        "Expression of Political Freedom: Cultural liberalism",
        "Expression of Political Freedom: Geolibertarianism",
        "Expression of Political Freedom: Green liberalism",
        "Expression of Political Freedom: Individualist feminism",
        "Expression of Political Freedom: Progressivism",
        "Expression of Political Freedom: Radicalism",
        "Expression of Political Freedom: Internationalism",
        "Expression of Political Freedom: Liberal nationalism",
        "Expression of Political Freedom: Nationalism",
        "Expression of Political Freedom: Romantic nationalism",
        "Expression of Political Freedom: Austrofascism",
        "Expression of Political Freedom: Chilean Fascism",
        "Expression of Political Freedom: Clerical fascism",
        "Expression of Political Freedom: Ecofascism",
        "Expression of Political Freedom: Falangism",
        "Expression of Political Freedom: Greek fascism",
        "Expression of Political Freedom: Italian fascism",
        "Expression of Political Freedom: Iron Guard",
        "Expression of Political Freedom: Japanese fascism",
        "Expression of Political Freedom: Nazism",
        "Expression of Political Freedom: Neo-Fascism",
        "Expression of Political Freedom: Rexism",
        "Expression of Political Freedom: Strasserism",
        "Expression of Political Freedom: Ustaše",
        "Expression of Political Freedom: Zbor",
        "Expression of Political Freedom: Kemalism",
        "Expression of Political Freedom: Brazilian Integralism",
        "Expression of Political Freedom: Gaullism",
        "Expression of Political Freedom: Irish Nationalism",
        "Expression of Political Freedom: Irish Republicanism",
        "Expression of Political Freedom: Peronism",
        "Expression of Political Freedom: Portuguese Integralism",
        "Expression of Political Freedom: Baathism",
        "Expression of Political Freedom: Nasserism",
        "Expression of Political Freedom: Zionism",
        "Expression of Political Freedom: Labor Zionism",
        "Expression of Political Freedom: Religious Zionism",
        "Expression of Political Freedom: Revisionist Zionism",
        "Expression of Political Freedom: Neo-Zionism",
        "Expression of Political Freedom: African socialism",
        "Expression of Political Freedom: Arab socialism",
        "Expression of Political Freedom: Pan-Africanism",
        "Expression of Political Freedom: Pan-Arabism",
        "Expression of Political Freedom: Pan-Iranism",
        "Expression of Political Freedom: Pan-European nationalism",
        "Expression of Political Freedom: Arab nationalism",
        "Expression of Political Freedom: Black nationalism",
        "Expression of Political Freedom: Chinese nationalism",
        "Expression of Political Freedom: Corporatism",
        "Expression of Political Freedom: Left-wing nationalism",
        "Expression of Political Freedom: National-Anarchism",
        "Expression of Political Freedom: National Bolshevism",
        "Expression of Political Freedom: National syndicalism",
        "Expression of Political Freedom: Patriotism",
        "Expression of Political Freedom: Producerism",
        "Expression of Political Freedom: Queer nationalism",
        "Expression of Political Freedom: White nationalism",
        "Expression of Political Freedom: Theocracy",
        "Expression of Political Freedom: Buddhist socialism",
        "Expression of Political Freedom: Christian anarchism",
        "Expression of Political Freedom: Christian communism",
        "Expression of Political Freedom: Christian democracy",
        "Expression of Political Freedom: Christian feminism",
        "Expression of Political Freedom: Christian socialism",
        "Expression of Political Freedom: Christian Left",
        "Expression of Political Freedom: Clerical fascism",
        "Expression of Political Freedom: Liberation Theology",
        "Expression of Political Freedom: Political Catholicism",
        "Expression of Political Freedom: Popolarismo",
        "Expression of Political Freedom: Christian Right",
        "Expression of Political Freedom: Christian Zionism",
        "Expression of Political Freedom: Christofascism",
        "Expression of Political Freedom: Dominionism",
        "Expression of Political Freedom: Caesaropapism",
        "Expression of Political Freedom: Ultramontanism",
        "Expression of Political Freedom: Hindu nationalism",
        "Expression of Political Freedom: Islamic democracy",
        "Expression of Political Freedom: Islamic socialism",
        "Expression of Political Freedom: Islamism",
        "Expression of Political Freedom: Khilafat",
        "Expression of Political Freedom: Panislamism",
        "Expression of Political Freedom: Jewish anarchism",
        "Expression of Political Freedom: Jewish feminism",
        "Expression of Political Freedom: Religious Zionism",
        "Expression of Political Freedom: Theodemocracy",
        "Expression of Political Freedom: United Order",
        "Expression of Political Freedom: Khalistan movement",
        "Expression of Political Freedom: Fourierism",
        "Expression of Political Freedom: Guild socialism",
        "Expression of Political Freedom: Revolutionary syndicalism",
        "Expression of Political Freedom: Gandhian economics",
        "Expression of Political Freedom: Zapatismo",
        "Expression of Political Freedom: Autonomism",
        "Expression of Political Freedom: Situationist International",
        "Expression of Political Freedom: Libertarian Marxism",
        "Expression of Political Freedom: Luxemburgism",
        "Expression of Political Freedom: Left communism",
        "Expression of Political Freedom: Council communism",
        "Expression of Political Freedom: Communization",
        "Expression of Political Freedom: Collectivist anarchism",
        "Expression of Political Freedom: Anarcho-communism",
        "Expression of Political Freedom: Anarcho-syndicalism",
        "Expression of Political Freedom: Social anarchism",
        "Expression of Political Freedom: Platformism",
        "Expression of Political Freedom: Social ecology",
        "Expression of Political Freedom: Participism",
        "Expression of Political Freedom: Inclusive Democracy",
        "Expression of Political Freedom: Communalism",
        "Expression of Political Freedom: Bernsteinism",
        "Expression of Political Freedom: Austromarxism",
        "Expression of Political Freedom: Bernsteinism",
        "Expression of Political Freedom: Democratic socialism",
        "Expression of Political Freedom: Fabianism",
        "Expression of Political Freedom: Reformism",
        "Expression of Political Freedom: Market socialism",
        "Expression of Political Freedom: Neosocialism",
        "Expression of Political Freedom: Social democracy",
        "Expression of Political Freedom: State socialism",
        "Expression of Political Freedom: African socialism",
        "Expression of Political Freedom: Arab socialism",
        "Expression of Political Freedom: Bolivarianism",
        "Expression of Political Freedom: Labor Zionism",
        "Expression of Political Freedom: Melanesian socialism",
        "Expression of Political Freedom: Revolutionary democracy",
        "Expression of Political Freedom: Religious socialism",
        "Expression of Political Freedom: Liberation Theology",
        "Expression of Political Freedom: Social capitalism",
        "Expression of Political Freedom: Socialist feminism",
        "Expression of Political Freedom: Quotaism",
        "Expression of Political Freedom: Autonomist Marxism",
        "Expression of Political Freedom: Castroism",
        "Expression of Political Freedom: Council communism",
        "Expression of Political Freedom: De Leonism",
        "Expression of Political Freedom: Eurocommunism",
        "Expression of Political Freedom: Guevarism",
        "Expression of Political Freedom: Hoxhaism",
        "Expression of Political Freedom: Kautskyism",
        "Expression of Political Freedom: Left communism",
        "Expression of Political Freedom: Leninism",
        "Expression of Political Freedom: Luxemburgism",
        "Expression of Political Freedom: Maoism",
        "Expression of Political Freedom: Marxism",
        "Expression of Political Freedom: Marxism–Leninism",
        "Expression of Political Freedom: Marxist feminism",
        "Expression of Political Freedom: Marxist humanism",
        "Expression of Political Freedom: Neo-marxism",
        "Expression of Political Freedom: Orthodox Marxism",
        "Expression of Political Freedom: Situationism",
        "Expression of Political Freedom: Anti-Revisionism",
        "Expression of Political Freedom: Titoism",
        "Expression of Political Freedom: Trotskyism",
        "Expression of Political Freedom: Western Marxism",
        "Expression of Political Freedom: Anarcho-syndicalism",
        "Expression of Political Freedom: Collectivist anarchism",
        "Expression of Political Freedom: Anarchist communism",
        "Expression of Political Freedom: Eco-socialism",
        "Expression of Political Freedom: Social anarchism",
        "Expression of Political Freedom: Social ecology",
        "Expression of Political Freedom: Individualist anarchism",
        "Expression of Political Freedom: Mutualist anarchism",
        "Expression of Political Freedom: Guild socialism",
        "Expression of Political Freedom: Libertarian socialism",
        "Expression of Political Freedom: Sankarism",
        "Expression of Political Freedom: Syndicalism",
        "Expression of Political Freedom: Utopian socialism",
        "Expression of Political Freedom: National Bolshevism",
        "Expression of Political Freedom: Realism",
        "Expression of Political Freedom: Authoritarianism",
        "Expression of Political Freedom: Anarchism",
        "Expression of Political Freedom: Centrism",
        "Expression of Political Freedom: Christian democracy",
        "Expression of Political Freedom: Communism",
        "Expression of Political Freedom: Communitarianism",
        "Expression of Political Freedom: Conservatism",
        "Expression of Political Freedom: Fascism",
        "Expression of Political Freedom: Feminism",
        "Expression of Political Freedom: Green politics",
        "Expression of Political Freedom: Hegemonic masculinity",
        "Expression of Political Freedom: Individualism",
        "Expression of Political Freedom: Islamism",
        "Expression of Political Freedom: Left-wing politics",
        "Expression of Political Freedom: Liberalism",
        "Expression of Political Freedom: Libertarianism",
        "Expression of Political Freedom: Monarchism",
        "Expression of Political Freedom: Nationalism",
        "Expression of Political Freedom: Republicanism",
        "Expression of Political Freedom: Right-wing politics",
        "Expression of Political Freedom: Social democracy",
        "Expression of Political Freedom: Socialism",
        "Expression of Political Freedom: Utilitarianism"
    };

    unsigned int size = sizeof(texts) / sizeof(texts[0]);

    for (unsigned int i = 0; i < size; i++)
        clamSpeechList.push_back(texts[i]);
}


boost::filesystem::path GetClamSpeechFile()
{
    boost::filesystem::path pathClamSpeechFile(GetArg("-clamspeech", "clamspeech.txt"));
    if (!pathClamSpeechFile.is_complete()) pathClamSpeechFile = GetDataDir() / pathClamSpeechFile;
    return pathClamSpeechFile;
}

boost::filesystem::path GetQuoteFile()
{
    boost::filesystem::path pathQuoteFile(GetArg("-quotes", "quotes.txt"));
    if (!pathQuoteFile.is_complete()) pathQuoteFile = GetDataDir() / pathQuoteFile;
    return pathQuoteFile;
}

boost::filesystem::path GetClamourClamSpeechFile()
{
    boost::filesystem::path pathClamourSpeechFile(GetArg("-clamourclamspeech", "clamourclamspeech.txt"));
    if (!pathClamourSpeechFile.is_complete()) pathClamourSpeechFile = GetDataDir() / pathClamourSpeechFile;
    return pathClamourSpeechFile;
}

string HashToString(unsigned char* hash,int n) {
    char outputBuffer[2*n+1];
    for(int i=0;i<n;i++) {
        sprintf(outputBuffer+(i*2),"%02x",hash[i]);
    }
    outputBuffer[2*n]=0;
    return string(outputBuffer);
}

bool LoadClamSpeech()
{

    if (clamSpeechList.empty())
    CSLoad();

    // If file doesn't exist, create it using the clamSpeech quote list
    if (!boost::filesystem::exists(GetClamSpeechFile())) {
        FILE* file = fopen(GetClamSpeechFile().string().c_str(), "w");
        if (file)
        {
        for(std::vector<std::string>::iterator it = clamSpeechList.begin(); it != clamSpeechList.end(); it++)
            {
                fprintf(file, "%s\n", it->c_str());
            }
            fclose(file);         
        }   
    }

    clamSpeech.clear();
    std::ifstream speechfile(GetClamSpeechFile().string().c_str());

    if(!speechfile) //Always test the file open.
        return false;

    string line;
    while (getline(speechfile, line, '\n'))
    {
        clamSpeech.push_back (line);
    }

    LoadClamourClamSpeech();
    
    return true;   
}

string GetRandomClamSpeech() {
    if(clamSpeech.empty()) {
        if(!LoadClamSpeech()) 
            return "This is a deafult quote that gets added in the event of all else failing";
    } 
    int index = rand() % clamSpeech.size();
    return clamSpeech[index];
}

string GetDefaultClamSpeech() {
    if (strDefaultSpeech == "")
        return GetRandomClamSpeech();

    return strDefaultSpeech;
}

string GetRandomClamourClamSpeech() {
    if (clamourClamSpeech.empty())
        return "";
    int index = rand() % clamourClamSpeech.size();
    return clamourClamSpeech[index];
}

string GetDefaultClamourClamSpeech() {
    if (strDefaultStakeSpeech == "")
        return GetRandomClamourClamSpeech();
    return strDefaultStakeSpeech;
}

bool SaveClamSpeech() 
{
    if (boost::filesystem::exists(GetClamSpeechFile())) {
        FILE* file = fopen(GetClamSpeechFile().string().c_str(), "w");
        if (file)
        {
        for(std::vector<std::string>::iterator it = clamSpeech.begin(); it != clamSpeech.end(); it++)
            {
                fprintf(file, "%s\n", it->c_str());
            }
            fclose(file);         
        }   
    } else {
        return false;
    }
    return true; 
}

bool LoadClamourClamSpeech()
{
    clamourClamSpeech.clear();
    std::ifstream speechfile(GetClamourClamSpeechFile().string().c_str());

    if(!speechfile) //Always test the file open.
        return false;

    string line;
    while (getline(speechfile, line, '\n'))
    {
        clamourClamSpeech.push_back (line);
    }
    
    return true;
}

bool SaveClamourClamSpeech()
{
    FILE* file = fopen(GetClamourClamSpeechFile().string().c_str(), "w");
    if (file)
    {
        for (std::vector<std::string>::iterator it = clamourClamSpeech.begin(); it != clamourClamSpeech.end(); it++) {
            fprintf(file, "%s\n", it->c_str());
        }
        fclose(file);
    } else {
        return false;
    }
    return true;
}

bool LoadQuoteList()
{

    // If file doesn't exist, create it using the clamSpeech quote list
    if (!boost::filesystem::exists(GetQuoteFile())) {
        FILE* file = fopen(GetQuoteFile().string().c_str(), "w");
        if (file)
        {
            fprintf(file, "### Personal quote file is empty. Add your own personal quotes here\n");
            fclose(file);         
        }   
    }

    quoteList.clear();
    std::ifstream quotefile(GetQuoteFile().string().c_str());

    if(!quotefile) //Always test the file open.
        return false;

    string line;
    while (getline(quotefile, line, '\n'))
    {
        quoteList.push_back (line);
    }
    return true;
}