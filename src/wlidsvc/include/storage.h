#pragma once

#include "util.h"
#include "log.h"
#include "types.h"

#include <string>

struct sqlite3;
struct sqlite3_stmt;

#define CREATE_METADATA_STORE_SQL \
    "CREATE TABLE IF NOT EXISTS metadata (\"key\" TEXT PRIMARY KEY, value TEXT);"

#define CREATE_CONFIG_STORE_SQL \
    "CREATE TABLE IF NOT EXISTS wlid_config (\"key\" TEXT PRIMARY KEY, value TEXT);"

#define CREATE_IDENTITY_STORE_SQL             \
    "CREATE TABLE IF NOT EXISTS identities (" \
    "  identity TEXT PRIMARY KEY NOT NULL,"   \
    "  puid INTEGER,"                         \
    "  cuid TEXT,"                            \
    "  email TEXT,"                           \
    "  display_name TEXT"                     \
    ");"

#define CREATE_IDENTITY_INDEX_SQL \
    "CREATE INDEX IF NOT EXISTS idx_identity_puid ON identities (puid);"

#define CREATE_TOKEN_STORE_SQL                                                   \
    "CREATE TABLE IF NOT EXISTS tokens ("                                        \
    "  identity TEXT NOT NULL,"                                                  \
    "  service TEXT NOT NULL,"                                                   \
    "  token TEXT,"                                                              \
    "  type TEXT,"                                                               \
    "  expires TEXT,"                                                            \
    "  created TEXT,"                                                            \
    "  PRIMARY KEY (identity, service),"                                         \
    "  FOREIGN KEY (identity) REFERENCES identities(identity) ON DELETE CASCADE" \
    ");"


#define DB_INIT               \
    CREATE_METADATA_STORE_SQL \
    CREATE_CONFIG_STORE_SQL   \
    CREATE_IDENTITY_STORE_SQL \
    CREATE_IDENTITY_INDEX_SQL \
    CREATE_TOKEN_STORE_SQL

namespace wlidsvc::storage
{
    constexpr int CURRENT_SCHEMA_VERSION = 2;

    class base_store_t
    {
    public:
        base_store_t(sqlite3 *db);
        base_store_t(const std::wstring &path, bool is_readonly = false);
        ~base_store_t();

    protected:
        sqlite3 *db = nullptr;
        bool owns_db = true;
        bool is_readonly = false;

        int exec(const char *sql, char **errmsg);
        int prepare(const char *sql, sqlite3_stmt **stmt);
        int step_and_finalize(sqlite3_stmt *stmt);
    };

    class config_store_t : protected base_store_t
    {
    public:
        config_store_t(sqlite3 *db);
        config_store_t(const std::wstring &path, bool is_readonly = false);
        ~config_store_t() = default;

        void set(const std::string &key, const std::string &value);
        std::string get(const std::string &key, const std::string &default_value = {});

        inline void set(const std::wstring &key, const std::wstring &value)
        {
            set(wlidsvc::util::wstring_to_utf8(key), wlidsvc::util::wstring_to_utf8(value));
        }

        inline std::wstring get(const std::wstring &key)
        {
            return wlidsvc::util::utf8_to_wstring(get(wlidsvc::util::wstring_to_utf8(key)));
        }
    };

    class identity_store_t : protected base_store_t
    {
    public:
        identity_store_t(const std::wstring &path, bool is_readonly = false);
        ~identity_store_t() = default;

        bool store(const identity_t &identity);
        bool retrieve(const std::string &identity, identity_t &out_identity);

        inline bool retrieve(const std::wstring &identity, identity_t &out_identity)
        {
            return retrieve(wlidsvc::util::wstring_to_utf8(identity), out_identity);
        }
    };

    class token_store_t : protected base_store_t
    {
    public:
        token_store_t(const std::wstring &path, bool is_readonly = false);
        ~token_store_t() = default;

        bool store(const token_t &token);
        bool retrieve(const std::string &identity, const std::string &service, token_t &out_token);

        inline bool retrieve(const std::wstring &identity, const std::wstring &service, token_t &out_token)
        {
            return retrieve(wlidsvc::util::wstring_to_utf8(identity), wlidsvc::util::wstring_to_utf8(service), out_token);
        }

        // todo: C++ iterators seem like hell
    };

    constexpr LPCWSTR g_configDBFolder = TEXT("\\ReLiveWP");
#ifdef IS_PRODUCTION_BUILD
    constexpr LPCWSTR g_configDBName = TEXT("\\wlidstor.db");
#else
    constexpr LPCWSTR g_configDBName = TEXT("\\wlidstor-int.db");
#endif
    const std::wstring db_path();
    int init_db(void);
}