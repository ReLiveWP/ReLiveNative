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

            return out_token.token.size() > 0;
        }

        sqlite3_finalize(stmt);
        return false;
    }

    bool token_store_t::remove(const token_t &token)
    {
        if (is_readonly)
        {
            LOG("Attempted to remove token from read-only store: %s", token.identity.c_str());
            return false;
        }

        util::critsect_t cs{&globals::g_dbCritSect};

        const char *sql = "DELETE FROM tokens WHERE identity = ? AND service = ?;";
        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare SQL statement for removing token. %s", sqlite3_errmsg(db));
            return false;
        }

        sqlite3_bind_text(stmt, 1, token.identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, token.service.c_str(), -1, SQLITE_TRANSIENT);

        if (step_and_finalize(stmt) != SQLITE_DONE)
        {
            LOG("Failed to remove token: %s", sqlite3_errmsg(db));
            return false;
        }

        LOG("Removed token for identity: %s, service: %s", token.identity.c_str(), token.service.c_str());

        return true;
    }

    token_store_t::forward_iterator::forward_iterator(token_store_t &store, const std::optional<std::string> &identity, bool is_end)
        : store(store), identity(identity)
    {
        if (is_end)
        {
            stmt = nullptr;
            return;
        }

        std::string sql = "SELECT identity, service, token, type, expires, created FROM tokens";
        if (identity.has_value())
        {
            sql += " WHERE identity = ?";
        }
        sql += ";";

        if (store.prepare(sql.c_str(), &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare SQL statement for token iterator. %s", sqlite3_errmsg(store.db));
            stmt = nullptr;
            return;
        }

        if (identity.has_value())
        {
            sqlite3_bind_text(stmt, 1, identity->c_str(), -1, SQLITE_TRANSIENT);
        }

        ++(*this);
    }

    token_store_t::forward_iterator::~forward_iterator()
    {
        if (stmt)
        {
            sqlite3_finalize(stmt);
        }
    }

    token_store_t::forward_iterator &token_store_t::forward_iterator::operator++()
    {
        if (stmt == nullptr)
        {
            current_token.reset();
            return *this;
        }

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            token_t token;
            token.identity = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            token.service = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            token.token = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
            token.type = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
            token.expires = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
            token.created = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));

            current_token = token;
        }
        else
        {
            current_token.reset();
            sqlite3_finalize(stmt);
            stmt = nullptr; // now it will compare equal to end()
        }

        return *this;
    }

    bool token_store_t::forward_iterator::operator!=(const forward_iterator &other) const
    {
        if (stmt == nullptr && other.stmt == nullptr)
        {
            return false;
        }

        if (stmt == nullptr || other.stmt == nullptr)
        {
            return true;
        }

        // iterators are not equal if they are from different stores or have different identities
        if (&store != &other.store || identity != other.identity)
        {
            return true;
        }

        // if both iterators are valid, compare their current tokens
        if (current_token.has_value() && other.current_token.has_value())
        {
            return !(current_token->identity == other.current_token->identity &&
                     current_token->service == other.current_token->service &&
                     current_token->token == other.current_token->token &&
                     current_token->type == other.current_token->type &&
                     current_token->expires == other.current_token->expires &&
                     current_token->created == other.current_token->created);
        }

        // one iterator is valid and the other is not, so they are not equal
        return true;
    }

    token_t token_store_t::forward_iterator::operator*() const
    {
        if (current_token.has_value())
        {
            return current_token.value();
        }

        return {};
    }
}