#include "storage.h"
#include "log.h"
#include <shlobj.h>
#include <sqlite3.h>

namespace wlidsvc::storage
{
    const std::wstring db_path()
    {
        WCHAR szAppData[MAX_PATH] = {0};
        SHGetSpecialFolderPath(NULL, szAppData, CSIDL_APPDATA, TRUE);

        const std::wstring folderPath = std::wstring(szAppData) + g_configDBFolder;
        if (GetFileAttributes(folderPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            CreateDirectory(folderPath.c_str(), NULL);
        }

        return folderPath + g_configDBName;
    }

    base_store_t::base_store_t(sqlite3 *db)
        : owns_db(false), db(db), is_readonly(false)
    {
    }

    base_store_t::base_store_t(const std::wstring &path, bool is_readonly)
        : owns_db(true), is_readonly(is_readonly)
    {
        std::string utf8path = wlidsvc::util::wstring_to_utf8(path);
        if (sqlite3_open(utf8path.c_str(), &db) != SQLITE_OK)
        {
            LOG("Failed to open DB at %s", utf8path.c_str());
            std::terminate();
        }
    }

    base_store_t::~base_store_t()
    {
        if (db && owns_db)
            sqlite3_close(db);
    }

    int base_store_t::exec(const char *sql, char **errmsg)
    {
        return sqlite3_exec(db, sql, nullptr, nullptr, errmsg);
    }

    int base_store_t::prepare(const char *sql, sqlite3_stmt **stmt)
    {
        return sqlite3_prepare_v2(db, sql, -1, stmt, nullptr);
    }

    int base_store_t::step_and_finalize(sqlite3_stmt *stmt)
    {
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return rc;
    }

    const char *DB_INIT =
        "CREATE TABLE IF NOT EXISTS metadata ("
        "  \"key\" TEXT PRIMARY KEY,"
        "  value TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS wlid_config("
        "  \"key\" TEXT PRIMARY KEY,"
        "  value TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS identities ("
        "  identity TEXT PRIMARY KEY,"
        "  puid INTEGER,"
        "  cuid TEXT,"
        "  email TEXT,"
        "  display_name TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_identity_puid ON identities (puid);"
        "CREATE TABLE IF NOT EXISTS tokens ("
        "  identity TEXT,"
        "  service TEXT,"
        "  token TEXT,"
        "  type TEXT,"
        "  expires TEXT,"
        "  created TEXT,"
        "  PRIMARY KEY (identity, service),"
        "  FOREIGN KEY (identity) REFERENCES identities(identity) ON DELETE CASCADE"
        ");";

    int init_db(void)
    {
        sqlite3 *db = nullptr;
        int code = SQLITE_OK;
        char *errmsg = nullptr;

        std::string schema_version = std::to_string(CURRENT_SCHEMA_VERSION);
        std::string utf8path = wlidsvc::util::wstring_to_utf8(db_path());
        if ((code = sqlite3_open(utf8path.c_str(), &db)) != SQLITE_OK)
        {
            LOG("%s%s", "Failed to open DB at ", utf8path.c_str());
            return code;
        }

        if ((code = sqlite3_exec(db, DB_INIT, nullptr, nullptr, &errmsg)) != SQLITE_OK)
        {
            LOG("Failed to initialize database: %s", errmsg);
            sqlite3_close(db);
            sqlite3_free(errmsg);
            return code;
        }

        const char *check_version_sql =
            "SELECT value FROM metadata WHERE key = 'schema_version';";

        sqlite3_stmt *stmt;
        if ((code = sqlite3_prepare_v2(db, check_version_sql, -1, &stmt, nullptr)) != SQLITE_OK)
        {
            LOG("SQLite error: %s", sqlite3_errmsg(db));
            sqlite3_close(db);
            sqlite3_finalize(stmt);
            return code;
        }

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            int version = std::stoi(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
            sqlite3_finalize(stmt);

            if (version < CURRENT_SCHEMA_VERSION)
            {
                const char *update_version_sql =
                    "UPDATE metadata SET value = ? WHERE key = 'schema_version';";

                sqlite3_stmt *update_stmt;
                sqlite3_prepare_v2(db, update_version_sql, -1, &update_stmt, nullptr);
                sqlite3_bind_text(update_stmt, 1, schema_version.c_str(), -1, SQLITE_TRANSIENT);
                if ((rc = sqlite3_step(update_stmt)) != SQLITE_DONE)
                {
                    sqlite3_finalize(update_stmt);
                    sqlite3_close(db);
                    LOG("SQLite error: %s", sqlite3_errmsg(db));
                    return rc;
                }
                sqlite3_finalize(update_stmt);
            }
        }
        else
        {
            sqlite3_finalize(stmt);
            const char *insert_version_sql =
                "INSERT INTO metadata (key, value) VALUES ('schema_version', ?);";

            sqlite3_stmt *insert_stmt;
            sqlite3_prepare_v2(db, insert_version_sql, -1, &insert_stmt, nullptr);
            sqlite3_bind_text(insert_stmt, 1, schema_version.c_str(), -1, SQLITE_TRANSIENT);
            if ((rc = sqlite3_step(insert_stmt)) != SQLITE_DONE)
            {
                sqlite3_finalize(insert_stmt);
                sqlite3_close(db);
                LOG("SQLite error: %s", sqlite3_errmsg(db));
                return rc;
            }
            sqlite3_finalize(insert_stmt);
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return code;
    }
}