#include "storage.h"
#include "log.h"
#include <sqlite3.h>
#include <wincrypt.h>
#include <base64.hpp>

namespace wlidsvc::storage
{
    // TODO: we need to hook these up with DPAPI, but we can't right now because doing so would 
    //       break existing stored plaintext tokens.
    
    std::string dpapi_protect(const std::string &plaintext)
    {
        // DATA_BLOB in{(DWORD)plaintext.size(), (BYTE *)plaintext.data()};
        // DATA_BLOB out{};
        // if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        //     return plaintext; // graceful degradation if DPAPI unavailable
        // std::string encoded = base64::to_base64(std::string(reinterpret_cast<char *>(out.pbData), out.cbData));
        // LocalFree(out.pbData);
        // return encoded;

        return plaintext;
    }

    std::string dpapi_unprotect(const std::string &encoded)
    {
        // if (encoded.empty())
        //     return encoded;
        // std::string cipher = base64::from_base64(encoded);
        // DATA_BLOB in{(DWORD)cipher.size(), (BYTE *)cipher.data()};
        // DATA_BLOB out{};
        // if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        //     return encoded; // return raw value if decryption fails (e.g., unencrypted legacy row)
        // std::string plaintext(reinterpret_cast<char *>(out.pbData), out.cbData);
        // LocalFree(out.pbData);
        // return plaintext;

        return encoded;
    }

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
            "INSERT INTO tokens (identity, service, token, type, expires, created, invalid) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(identity, service) DO UPDATE SET "
            "token = excluded.token, type = excluded.type, expires = excluded.expires, "
            "created = excluded.created, invalid = excluded.invalid;";

        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare SQL statement for storing token. %s", sqlite3_errmsg(db));
            return false;
        }

        std::string encrypted_token = dpapi_protect(token.token);
        sqlite3_bind_text(stmt, 1, token.identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, token.service.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, encrypted_token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, token.type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, token.expires.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, token.created.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, token.invalid ? 1 : 0);

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

        const char *sql = "SELECT token, type, expires, created, invalid FROM tokens WHERE identity = ? AND service = ?;";
        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare token retrieve: %s", sqlite3_errmsg(db));
            return false;
        }
        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_TRANSIENT);

        auto col_str = [&](int col) -> std::string {
            const unsigned char *v = sqlite3_column_text(stmt, col);
            return v ? reinterpret_cast<const char *>(v) : "";
        };

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            out_token.identity = identity;
            out_token.service = service;
            out_token.token = dpapi_unprotect(col_str(0));
            out_token.type = col_str(1);
            out_token.expires = col_str(2);
            out_token.created = col_str(3);
            out_token.invalid = sqlite3_column_int(stmt, 4) != 0;
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

        std::string sql = "SELECT identity, service, token, type, expires, created, invalid FROM tokens";
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
            auto col_str = [&](int col) -> std::string {
                const unsigned char *v = sqlite3_column_text(stmt, col);
                return v ? reinterpret_cast<const char *>(v) : "";
            };
            token_t token;
            token.identity = col_str(0);
            token.service = col_str(1);
            token.token = dpapi_unprotect(col_str(2));
            token.type = col_str(3);
            token.expires = col_str(4);
            token.created = col_str(5);
            token.invalid = sqlite3_column_int(stmt, 6) != 0;

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

    bool token_store_t::mark_invalid(const std::string &identity, const std::string &service)
    {
        if (is_readonly)
        {
            LOG("Attempted to mark token invalid in read-only store: %s", identity.c_str());
            return false;
        }

        util::critsect_t cs{&globals::g_dbCritSect};

        const char *sql = "UPDATE tokens SET invalid = 1 WHERE identity = ? AND service = ?;";
        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare mark_invalid: %s", sqlite3_errmsg(db));
            return false;
        }

        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_TRANSIENT);

        if (step_and_finalize(stmt) != SQLITE_DONE)
        {
            LOG("Failed to mark token invalid for identity: %s, service: %s", identity.c_str(), service.c_str());
            return false;
        }

        LOG("Marked token invalid for identity: %s, service: %s", identity.c_str(), service.c_str());
        return true;
    }
}