#pragma once

#include "util.h"
#include "log.h"

#include <string>
#include <sqlite3.h>

namespace wlidsvc::storage
{
    constexpr int CURRENT_SCHEMA_VERSION = 1;

    class config_store_t
    {
    public:
        config_store_t(sqlite3 *db)
            : owns_db(false), db(db), is_readonly(false)
        {
        }

        config_store_t(const std::wstring &path, bool is_readonly = false)
            : owns_db(true), is_readonly(is_readonly)
        {
            std::string utf8path = wlidsvc::util::wstring_to_utf8(path);
            if (sqlite3_open(utf8path.c_str(), &db) != SQLITE_OK)
            {
                LOG("Failed to open DB at %s", utf8path.c_str());
                std::terminate();
            }

            if (is_readonly)
                return;

            if (exec("CREATE TABLE IF NOT EXISTS wlid_config (key TEXT PRIMARY KEY, value TEXT);", nullptr) != SQLITE_OK)
            {
                LOG("Failed to create wlid_config table. %s", sqlite3_errmsg(db));
                std::terminate();
            }
        }

        ~config_store_t()
        {
            if (db && owns_db)
                sqlite3_close(db);
        }

        void set(const std::string &key, const std::string &value)
        {
            if (is_readonly)
            {
                LOG("Attempted to set value in read-only config store: %s", key.c_str());
                return;
            }

            const char *sql =
                "INSERT INTO wlid_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";

            sqlite3_stmt *stmt;
            prepare(sql, &stmt);
            sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
            step_and_finalize(stmt);
        }

        std::string get(const std::string &key, const std::string &default_value = {})
        {
            const char *sql = "SELECT value FROM wlid_config WHERE key = ?;";
            sqlite3_stmt *stmt;
            prepare(sql, &stmt);
            sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

            int rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW)
            {
                std::string val(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
                sqlite3_finalize(stmt);
                return val;
            }
            sqlite3_finalize(stmt);
            return default_value;
        }

        void set(const std::wstring &key, const std::wstring &value)
        {
            set(wlidsvc::util::wstring_to_utf8(key), wlidsvc::util::wstring_to_utf8(value));
        }

        std::wstring get(const std::wstring &key)
        {
            return wlidsvc::util::utf8_to_wstring(get(wlidsvc::util::wstring_to_utf8(key)));
        }

    private:
        sqlite3 *db = nullptr;
        bool owns_db = true;
        bool is_readonly = false;

        int exec(const char *sql, char **errmsg)
        {
            return sqlite3_exec(db, sql, nullptr, nullptr, errmsg);
        }

        int prepare(const char *sql, sqlite3_stmt **stmt)
        {
            return sqlite3_prepare_v2(db, sql, -1, stmt, nullptr);
        }

        int step_and_finalize(sqlite3_stmt *stmt)
        {
            int rc = sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            return rc;
        }
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