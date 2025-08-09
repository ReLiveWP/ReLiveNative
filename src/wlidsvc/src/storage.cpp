#include "storage.h"
#include "log.h"
#include <shlobj.h>

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

        const char *create_metadata_sql =
            "CREATE TABLE IF NOT EXISTS metadata ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT"
            ");";

        if ((code = sqlite3_exec(db, create_metadata_sql, nullptr, nullptr, &errmsg)) != SQLITE_OK)
        {
            LOG("Failed to create metadata table: %s", errmsg);
            sqlite3_free(errmsg);
            return code;
        }

        const char *create_config_sql =
            "CREATE TABLE IF NOT EXISTS wlid_config ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT"
            ");";

        if ((code = sqlite3_exec(db, create_config_sql, nullptr, nullptr, &errmsg)) != SQLITE_OK)
        {
            LOG("Failed to create wlid_config table: %s", errmsg);
            sqlite3_free(errmsg);
            return code;
        }

        const char *check_version_sql =
            "SELECT value FROM metadata WHERE key = 'schema_version';";

        sqlite3_stmt *stmt;
        if ((code = sqlite3_prepare_v2(db, check_version_sql, -1, &stmt, nullptr)) != SQLITE_OK)
        {
            LOG("SQLite error: %s", sqlite3_errmsg(db));
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
                LOG("SQLite error: %s", sqlite3_errmsg(db));
                return rc;
            }
            sqlite3_finalize(insert_stmt);
        }
    close:
        sqlite3_close(db);
        return code;
    }
}