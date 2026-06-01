#include "storage.h"
#include "log.h"
#include <sqlite3.h>

namespace wlidsvc::storage
{
    std::string dpapi_protect(const std::string &plaintext);
    std::string dpapi_unprotect(const std::string &encoded);

    identity_token_store_t::identity_token_store_t(const std::wstring &path, const std::string &identity, bool is_readonly)
        : base_store_t(path, is_readonly), identity(identity)
    {
        if (is_readonly)
            return;

        util::critsect_t cs{&globals::g_dbCritSect};
        if (exec(CREATE_IDENTITY_PROPERTY_STORE_SQL, nullptr) != SQLITE_OK)
        {
            LOG("Failed to create identity_properties table. %s", sqlite3_errmsg(db));
        }
    }

    bool identity_token_store_t::set(const std::string &key, const std::string &value)
    {
        if (is_readonly)
        {
            LOG("Attempted to set value in read-only config store: %s", key.c_str());
            return false;
        }

        util::critsect_t cs{&globals::g_dbCritSect};

        const char *sql =
            "INSERT INTO identity_properties (identity, propkey, propvalue) VALUES (?, ?, ?) "
            "ON CONFLICT(identity, propkey) DO UPDATE SET propvalue = excluded.propvalue;";

        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare SQL statement for storing identity property. %s", sqlite3_errmsg(db));
            return false;
        }

        auto protected_value = dpapi_protect(value);
        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, protected_value.c_str(), -1, SQLITE_TRANSIENT);
        if (step_and_finalize(stmt) != SQLITE_DONE)
        {
            LOG("Failed to store identity property: %s", sqlite3_errmsg(db));
            return false;
        }

        return true;
    }

    bool identity_token_store_t::get(const std::string &key, std::string &value)
    {
        const char *sql = "SELECT propvalue FROM identity_properties WHERE identity = ? AND propkey = ?;";
        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare identity_properties get: %s", sqlite3_errmsg(db));
            return false;
        }
        sqlite3_bind_text(stmt, 1, identity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            const unsigned char *col = sqlite3_column_text(stmt, 0);
            value = col ? dpapi_unprotect(reinterpret_cast<const char *>(col)) : "";
            sqlite3_finalize(stmt);
            return true;
        }

        sqlite3_finalize(stmt);
        return false;
    }

    bool identity_token_store_t::find_identities_for_credential_type(const std::wstring credential_type, std::vector<std::wstring> &identities)
    {
        const char *sql = "SELECT identity FROM identity_properties WHERE propkey = ?;";
        sqlite3_stmt *stmt;
        if (prepare(sql, &stmt) != SQLITE_OK)
        {
            LOG("Failed to prepare find_identities statement: %s", sqlite3_errmsg(db));
            return false;
        }
        std::string cred_utf8 = util::wstring_to_utf8(credential_type);
        sqlite3_bind_text(stmt, 1, cred_utf8.c_str(), -1, SQLITE_TRANSIENT);

        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            const unsigned char *col = sqlite3_column_text(stmt, 0);
            if (col)
            {
                auto unencrypted_token = dpapi_unprotect(reinterpret_cast<const char *>(col));
                identities.push_back(util::utf8_to_wstring(unencrypted_token));
            }
        }

        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }
}