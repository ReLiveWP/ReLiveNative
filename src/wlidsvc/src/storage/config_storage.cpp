#include "storage.h"
#include "log.h"
#include <sqlite3.h>

namespace wlidsvc::storage
{
    config_store_t::config_store_t(sqlite3 *db)
        : base_store_t(db)
    {
    }

    config_store_t::config_store_t(const std::wstring &path, bool is_readonly)
        : base_store_t(path, is_readonly)
    {
        if (is_readonly)
            return;

        util::critsect_t cs{&globals::g_dbCritSect};
        if (exec(CREATE_CONFIG_STORE_SQL, nullptr) != SQLITE_OK)
        {
            LOG("Failed to create wlid_config table. %s", sqlite3_errmsg(db));
        }
    }

    void config_store_t::set(const std::string &key, const std::string &value)
    {
        if (is_readonly)
        {
            LOG("Attempted to set value in read-only config store: %s", key.c_str());
            return;
        }

        util::critsect_t cs{&globals::g_dbCritSect};

        const char *sql =
            "INSERT INTO wlid_config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";

        sqlite3_stmt *stmt;
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
        step_and_finalize(stmt);
    }

    std::string config_store_t::get(const std::string &key, const std::string &default_value)
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
}