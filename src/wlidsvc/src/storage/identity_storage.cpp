#include "storage.h"
#include "log.h"
#include <sqlite3.h>

#include "util.h"

#define SELECT_IDENTITY_SQL \
    "SELECT puid, cuid, email, display_name FROM identities WHERE identity = ?;"

#define INSERT_IDENTITY_SQL                                               \
    "INSERT INTO identities (identity, puid, cuid, email, display_name) " \
    "VALUES (?, ?, ?, ?, ?) "                                             \
    "ON CONFLICT(identity) DO UPDATE SET "                                \
    "puid = excluded.puid, cuid = excluded.cuid, email = excluded.email, display_name = excluded.display_name;"

namespace wlidsvc::storage
{
    identity_store_t::identity_store_t(const std::wstring &path, bool is_readonly)
        : base_store_t(path, is_readonly)
    {
        if (is_readonly)
            return;

        util::critsect_t cs{&globals::g_dbCritSect};
        if (exec(CREATE_IDENTITY_STORE_SQL, nullptr) != SQLITE_OK)
        {
            LOG("Failed to create identity table. %s", sqlite3_errmsg(db));
        }

        if (exec(CREATE_IDENTITY_INDEX_SQL, nullptr) != SQLITE_OK)
        {
            LOG("Failed to create identity index. %s", sqlite3_errmsg(db));
        }
    }

    bool identity_store_t::store(const identity_t &identity)
    {
        if (is_readonly)
        {
            LOG("Attempted to store identity in read-only store: %s", identity.identity.c_str());
            return false;
        }

        util::critsect_t cs{&globals::g_dbCritSect};

        sqlite3_stmt *stmt;
        if (prepare(INSERT_IDENTITY_SQL, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare SQL statement for storing identity. %s", sqlite3_errmsg(db));
            return false;
        }

        sqlite3_bind_text(stmt, 1, identity.identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, identity.puid);
        sqlite3_bind_text(stmt, 3, identity.cid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, identity.email.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, identity.display_name.c_str(), -1, SQLITE_TRANSIENT);
        if (step_and_finalize(stmt) != SQLITE_DONE)
        {
            LOG("Failed to store identity: %s (PUID: %llu, CUID: %s, Email: %s), %s",
                identity.identity.c_str(),
                identity.puid,
                identity.cid.c_str(),
                identity.email.c_str(),
                sqlite3_errmsg(db));

            return false;
        }

        LOG("Stored identity: %s (PUID: %llu, CUID: %s, Email: %s)",
            identity.identity.c_str(),
            identity.puid,
            identity.cid.c_str(),
            identity.email.c_str());

        return true;
    }

    bool identity_store_t::retrieve(const std::string &identity, identity_t &out_identity)
    {
        LOG("Retrieving identity: %s", identity.c_str());

        sqlite3_stmt *stmt;
        if (prepare(SELECT_IDENTITY_SQL, &stmt) != SQLITE_OK)
        {
            LOG("%s", "Failed to prepare SQL statement for retrieving identity.");
            return false;
        }
        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            auto col_str = [&](int col) -> std::string
            {
                const unsigned char *v = sqlite3_column_text(stmt, col);
                return v ? reinterpret_cast<const char *>(v) : "";
            };
            out_identity.identity = identity;
            out_identity.puid = sqlite3_column_int64(stmt, 0);
            out_identity.cid = col_str(1);
            out_identity.email = col_str(2);
            out_identity.display_name = col_str(3);
            sqlite3_finalize(stmt);
            return true;
        }

        sqlite3_finalize(stmt);
        return false;
    }
}