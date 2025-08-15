#include "storage.h"
#include "log.h"
#include <sqlite3.h>

namespace wlidsvc::storage
{
    token_store_t::token_store_t(const std::wstring &path, bool is_readonly)
        : base_store_t(path, is_readonly)
    {
        if (is_readonly)
            return;

        util::critsect_t cs{&globals::g_dbCritSect};
        if (exec(CREATE_TOKEN_STORE_SQL, nullptr) != SQLITE_OK)
        {
            LOG("Failed to create tokens table. %s", sqlite3_errmsg(db));
        }
    }

    bool token_store_t::store(const token_t &token)
    {
        if (is_readonly)
        {
            LOG("Attempted to store token in read-only store: %s", token.identity.c_str());
            return false;
        }

        util::critsect_t cs{&globals::g_dbCritSect};

        const char *sql =
            "INSERT INTO tokens (identity, service, token, type, expires, created) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(identity, service) DO UPDATE SET "
            "token = excluded.token, type = excluded.type, expires = excluded.expires, created = excluded.created;";

        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare SQL statement for storing token. %s", sqlite3_errmsg(db));
            return false;
        }

        sqlite3_bind_text(stmt, 1, token.identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, token.service.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, token.token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, token.type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, token.expires.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, token.created.c_str(), -1, SQLITE_TRANSIENT);

        if (step_and_finalize(stmt) != SQLITE_DONE)
        {
            LOG("Failed to store token: %s", sqlite3_errmsg(db));
            return false;
        }

        LOG("Stored token for identity: %s, service: %s", token.identity.c_str(), token.service.c_str());

        return true;
    }

    bool token_store_t::retrieve(const std::string &identity, const std::string &service, token_t &out_token)
    {
        LOG("Retrieving token for identity: %s, service: %s", identity.c_str(), service.c_str());

        const char *sql = "SELECT token, type, expires, created FROM tokens WHERE identity = ? AND service = ?;";
        sqlite3_stmt *stmt;
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            out_token.identity = identity;
            out_token.service = service;
            out_token.token = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            out_token.type = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            out_token.expires = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
            out_token.created = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
            sqlite3_finalize(stmt);
            return true;
        }

        sqlite3_finalize(stmt);
        return false;
    }
}