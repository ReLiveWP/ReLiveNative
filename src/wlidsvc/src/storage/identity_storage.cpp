#include "storage.h"
#include "log.h"
#include <sqlite3.h>

namespace wlidsvc::storage
{
    identity_store_t::identity_store_t(const std::wstring &path, bool is_readonly)
        : base_store_t(path, is_readonly)
    {
    }

    identity_store_t::~identity_store_t()
    {
    }

    void identity_store_t::store(const identity_t &identity)
    {
        if (is_readonly)
        {
            LOG("Attempted to store identity in read-only store: %s", identity.identity.c_str());
            return;
        }

        const char *sql =
            "INSERT INTO identities (identity, puid, cuid, email, display_name) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(identity) DO UPDATE SET "
            "puid = excluded.puid, cuid = excluded.cuid, email = excluded.email, display_name = excluded.display_name;";

        sqlite3_stmt *stmt;
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, identity.identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, identity.puid);
        sqlite3_bind_text(stmt, 3, identity.cuid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, identity.email.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, identity.display_name.c_str(), -1, SQLITE_TRANSIENT);
        step_and_finalize(stmt);

        LOG("Stored identity: %s", identity.identity.c_str());
    }

    bool identity_store_t::retrieve(const std::string &identity, identity_t &out_identity)
    {
        LOG("Retrieving identity: %s", identity.c_str());

        const char *sql = "SELECT puid, cuid, email, display_name FROM identities WHERE identity = ?;";
        sqlite3_stmt *stmt;
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            out_identity.identity = identity;
            out_identity.puid = sqlite3_column_int64(stmt, 0);
            out_identity.cuid = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            out_identity.email = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
            out_identity.display_name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
            sqlite3_finalize(stmt);
            return true;
        }

        sqlite3_finalize(stmt);
        return false;
    }
}