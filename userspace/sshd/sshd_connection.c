#include "sshd.h"
#include "sshd_auth.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>
#include "sshd_internal.h"
#include "sshd_connection_support.h"
#include "sshd_config.h"
#include "sshd_service.h"

/* ---- Connection State Machine Processor ---- */

/* Process one step for a connection. Returns 0 if connection should remain,
   -1 if closed/done. */
int process_connection(ssh_connection_t *conn) {
  int sockfd = (int)conn->sockfd;
  ssh_packet_t *pkt = &ssh_conn_scratch()->pkt;
  uint64_t now = sshd_timer_now();

  if (conn->state == SSH_STATE_INIT) {
    /* Send server version */
    if (ssh_send_version(sockfd) != 0) {
      ssh_log(SSH_LOG_ERROR, "Failed to send version\n");
      return -1;
    }
    conn->state = SSH_STATE_KEX;
    conn->kex_start_time = now;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX) {
    /* Receive client version */
    if (conn->version_len == 0U ||
        conn->version_buf[conn->version_len - 1U] != '\n') {
      while (conn->version_len < sizeof(conn->version_buf)) {
        u64 n = 0;
        int status = xaios_net_recv(conn->sockfd,
            conn->version_buf + conn->version_len, 1, &n);
        if (status != 0) return sshd_close_because("peer-gone");
        if (n == 0) return 0;
        conn->version_len += (uint32_t)n;
        if (conn->version_buf[conn->version_len - 1U] == '\n') break;
      }
      if (conn->version_len == sizeof(conn->version_buf) &&
          conn->version_buf[conn->version_len - 1U] != '\n') {
        return sshd_close_because("client-version-too-long");
      }
    }
    if (!sshd_valid_client_version(conn->version_buf, conn->version_len)) {
      ssh_log(SSH_LOG_WARN, "Rejected invalid SSH client version");
      return sshd_close_because("client-version-invalid");
    }

    if (send_server_kexinit(conn, 0) != 0) return -1;
    conn->state = SSH_STATE_KEX_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX_SENT) {
    /* Receive client KEXINIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return sshd_close_because("packet-read-failed");
    if (validate_client_kexinit(conn, pkt) != 0) return -1;
    init_exchange_hash(conn, pkt);
    conn->state = SSH_STATE_NEWKEYS;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS) {
    /* KEXDH_INIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return sshd_close_because("packet-read-failed");
    if (handle_kexdh_init(conn, pkt, 0) != 0) return -1;
    conn->state = SSH_STATE_NEWKEYS_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS_SENT) {
    /* Receive NEWKEYS */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return sshd_close_because("packet-read-failed");
    if (pkt->len == 0 || pkt->data[0] != 21) return -1;

    if (conn_init_encryption(conn) != 0) return -1;

    ssh_log(SSH_LOG_INFO, "KEX completed for connection %llx\n", conn->sockfd);
    conn->kex_start_time = now;
    conn->state = SSH_STATE_AUTH;
    return 0;
  }

  if (conn->state == SSH_STATE_REKEY_KEXINIT) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0 || validate_client_kexinit(conn, pkt) != 0)
      return -1;
    init_exchange_hash(conn, pkt);
    conn->state = SSH_STATE_REKEY_DH;
    return 0;
  }

  if (conn->state == SSH_STATE_REKEY_DH) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0 || handle_kexdh_init(conn, pkt, 1) != 0) return -1;
    conn->state = SSH_STATE_REKEY_NEWKEYS;
    return 0;
  }

  if (conn->state == SSH_STATE_REKEY_NEWKEYS) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0 || pkt->len != 1U ||
        pkt->data[0] != SSH_MSG_NEWKEYS) return -1;
    uint64_t encrypt_seq = conn->crypto.encrypt_seq;
    uint64_t decrypt_seq = conn->crypto.decrypt_seq;
    conn->crypto = conn->pending_crypto;
    conn->crypto.encrypt_seq = encrypt_seq;
    conn->crypto.decrypt_seq = decrypt_seq;
    ssh_mem_zero(&conn->pending_crypto, sizeof(conn->pending_crypto));
    conn->rekey_encrypt_base = encrypt_seq;
    conn->kex_start_time = now;
    conn->state = conn->rekey_resume_state;
    ssh_log(SSH_LOG_INFO, "Rekey completed for connection %llx\n",
            conn->sockfd);
    return 0;
  }

  if (conn->state == SSH_STATE_AUTH) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return sshd_close_because("packet-read-failed");
    if (pkt->len == 0) return 0;
    uint8_t msg = pkt->data[0];

    if (msg == SSH_MSG_KEXINIT) {
      return begin_client_rekey(conn, pkt, SSH_STATE_AUTH, now);
    }

    if (msg == SSH_MSG_SERVICE_REQUEST) {
      if (pkt->len < 5U) return -1;
      uint32_t requested_len = ssh_read_u32_be(pkt->data + 1U);
      static const char requested_service[] = "ssh-userauth";
      if (requested_len != sizeof(requested_service) - 1U ||
          pkt->len != 5U + requested_len ||
          !sshd_bytes_equal(pkt->data + 5U,
                       (const uint8_t *)requested_service, requested_len)) {
        return -1;
      }
      uint8_t sa[32];
      sa[0] = SSH_MSG_SERVICE_ACCEPT;
      const char *svc = requested_service;
      uint32_t svc_len = ssh_str_len(svc);
      ssh_write_u32_be(sa + 1, svc_len);
      ssh_mem_copy(sa + 5, svc, svc_len);
      conn_packet_write_encrypted(conn, sa, 5 + svc_len);
      return 0;
    }

    if (msg == SSH_MSG_USERAUTH_REQUEST) {
      uint32_t offset = 1;
      if (offset + 4U > pkt->len) return 0;
      uint32_t user_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (user_len > 64U || offset + user_len > pkt->len ||
          sshd_bytes_have_zero(pkt->data + offset, user_len)) return -1;
      char username[65];
      ssh_mem_copy(username, pkt->data + offset, user_len);
      username[user_len] = '\0';
      offset += user_len;

      if (offset + 4U > pkt->len) return 0;
      uint32_t service_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (service_len > 64U || offset + service_len > pkt->len ||
          sshd_bytes_have_zero(pkt->data + offset, service_len)) return -1;
      char service[65];
      ssh_mem_copy(service, pkt->data + offset, service_len);
      service[service_len] = '\0';
      offset += service_len;
      if (!ssh_str_eq(service, "ssh-connection")) return 0;

      if (offset + 4U > pkt->len) return 0;
      uint32_t method_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (method_len > 64U || offset + method_len > pkt->len ||
          sshd_bytes_have_zero(pkt->data + offset, method_len)) return -1;
      char method[65];
      ssh_mem_copy(method, pkt->data + offset, method_len);
      method[method_len] = '\0';
      offset += method_len;
      uint32_t auth_data_offset = offset;

      if (check_rate_limit(&conn->client_addr) != 0) {
        if (sshd_send_auth_failure(conn) != 0) return -1;
        return 0;
      }

      if (conn->auth_attempts >= g_runtime_config.max_auth_attempts) {
        record_auth_failure(&conn->client_addr);
        if (sshd_send_auth_failure(conn) != 0) return -1;
        return 0;
      }

      /* ---- "password" method ---- */
      if (ssh_str_eq(method, "password")) {
        if (g_password_auth_enabled == 0U || sshd_auth_user_count() == 0U) {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (sshd_send_auth_failure(conn) != 0) return -1;
          return 0;
        }
        uint32_t password_offset = auth_data_offset;
        if (password_offset + 5U > pkt->len) return 0;
        if (pkt->data[password_offset] != 0U) return 0;
        password_offset += 1U;
        uint32_t pass_len = ssh_read_string_len(pkt->data + password_offset);
        if (pass_len > 128U || password_offset + 4U + pass_len > pkt->len ||
            sshd_bytes_have_zero(pkt->data + password_offset + 4U, pass_len)) {
          return -1;
        }
        char password[129];
        ssh_mem_copy(password, pkt->data + password_offset + 4U, pass_len);
        password[pass_len] = '\0';

        int authenticated = sshd_auth_password_verify(username, password);
        ssh_mem_zero(password, sizeof(password));
        if (authenticated == 0) {
          uint8_t auth_reply[1] = {SSH_MSG_USERAUTH_SUCCESS};
          if (conn_packet_write_encrypted(conn, auth_reply,
                                          sizeof(auth_reply)) != 0) return -1;
          conn->auth_attempts = 0;
          record_auth_success(&conn->client_addr);
          ssh_log(SSH_LOG_INFO, "Password auth success: '%s'\n", username);
          conn->principal_role = XAIOS_CONTROL_ROLE_ADMIN;
          ssh_mem_copy(conn->principal, "password-admin",
                       sizeof("password-admin"));
          conn->state = SSH_STATE_AUTHENTICATED;
        } else {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (sshd_send_auth_failure(conn) != 0) return -1;
          ssh_log(SSH_LOG_WARN, "Password auth failed: '%s'\n", username);
        }
        return 0;
      }

      /* ---- "publickey" method (RFC 4252 Section 7) ---- */
      if (ssh_str_eq(method, "publickey")) {
        /* What authorises a public-key login is the key, checked below
           against the authorized keys; the username is the identity it
           claims. Asking the *password* database whether that name exists
           refuses every key login on a key-only image, where that database is
           empty by design -- which is what this did, and what stopped two
           interoperability gates. */
        char account[SSHD_USERNAME_MAX];
        (void)sshd_auth_account_name(account, sizeof(account));
        if (!sshd_auth_user_exists(username) &&
            !ssh_str_eq(username, account)) {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (sshd_send_auth_failure(conn) != 0) return -1;
          return 0;
        }
        offset = auth_data_offset;
        if (offset >= pkt->len) return 0;
        uint8_t has_signature = pkt->data[offset];
        if (has_signature > 1U) return 0;
        offset += 1;

        /* Read public key algorithm */
        if (offset > pkt->len || pkt->len - offset < 4U) return 0;
        uint32_t algo_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (algo_len > pkt->len - offset) return 0;
        const uint8_t *algorithm = pkt->data + offset;
        if (algo_len != 11U ||
            !sshd_bytes_equal(algorithm, (const uint8_t *)"ssh-ed25519", 11U)) {
          return 0;
        }
        offset += algo_len;

        /* Read public key blob */
        if (pkt->len - offset < 4U) return 0;
        uint32_t pubkey_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (pubkey_len > pkt->len - offset) return 0;
        const uint8_t *pubkey_blob = pkt->data + offset;
        uint8_t client_pubkey[32];
        if (sshd_keys_blob_parse(pubkey_blob, pubkey_len,
                                 client_pubkey) != 0) return 0;
        offset += pubkey_len;
        uint32_t signed_request_len = offset;

        sshd_keys_entry_t authorized;
        int authorized_found = 0;
        ssh_mem_zero(&authorized, sizeof(authorized));
        if (sshd_keys_load() == 0) {
          authorized_found = sshd_keys_lookup(client_pubkey, &authorized) == 0;
        }
        if (!authorized_found) {
          xaios_log("sshd: presented public key was not authorized\n");
          ssh_log(SSH_LOG_WARN, "Public key not authorized\n");
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (sshd_send_auth_failure(conn) != 0) return -1;
          return 0;
        }

        if (!has_signature) {
          /* Test request: public key is acceptable */
          uint8_t pk_ok[96];
          pk_ok[0] = SSH_MSG_USERAUTH_PK_OK;
          uint32_t poff = 1;
          ssh_write_u32_be(pk_ok + poff, algo_len); poff += 4;
          ssh_mem_copy(pk_ok + poff, algorithm, algo_len);
          poff += algo_len;
          ssh_write_u32_be(pk_ok + poff, pubkey_len); poff += 4;
          ssh_mem_copy(pk_ok + poff, pubkey_blob, pubkey_len);
          poff += pubkey_len;
          if (conn_packet_write_encrypted(conn, pk_ok, poff) != 0) return -1;
          return 0;
        }

        /* Read signature blob */
        if (pkt->len - offset < 4U) return 0;
        uint32_t sig_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (sig_len != pkt->len - offset) return 0;
        uint8_t *sig_blob = pkt->data + offset;

        /* Parse signature: string algorithm + string (R,s) */
        if (sig_len < 4U) return 0;
        uint32_t sig_algo_len = ssh_read_string_len(sig_blob);
        if (sig_algo_len != 11U || sig_algo_len > sig_len - 4U ||
            !sshd_bytes_equal(sig_blob + 4U,
                         (const uint8_t *)"ssh-ed25519", 11U)) return 0;
        uint32_t sig_data_off = 4U + sig_algo_len;
        if (sig_data_off > sig_len || sig_len - sig_data_off < 4U) return 0;
        uint32_t sig_data_len = ssh_read_string_len(sig_blob + sig_data_off);
        if (sig_data_len != sig_len - sig_data_off - 4U) return 0;
        uint8_t *sig_data = sig_blob + sig_data_off + 4;
        if (sig_data_len != 64) return 0;

        /* RFC 4252 signs string(session_id) followed by the request through
         * the public-key blob, excluding the signature field. */
        uint8_t verify_buf[SSH_PLAINTEXT_PACKET_SIZE + 36U];
        uint32_t vpos = 0;
        ssh_write_u32_be(verify_buf + vpos, 32U);
        vpos += 4U;
        ssh_mem_copy(verify_buf + vpos, conn->session_id, 32U);
        vpos += 32U;
        if (signed_request_len > SSH_PLAINTEXT_PACKET_SIZE) return 0;
        ssh_mem_copy(verify_buf + vpos, pkt->data, signed_request_len);
        vpos += signed_request_len;

        int verify_result = xaios_ed25519_verify(sig_data, verify_buf, vpos,
                                                  client_pubkey);
        if (verify_result == 0) {
          uint8_t auth_reply[1] = {SSH_MSG_USERAUTH_SUCCESS};
          if (conn_packet_write_encrypted(conn, auth_reply,
                                          sizeof(auth_reply)) != 0) return -1;
          conn->auth_attempts = 0;
          record_auth_success(&conn->client_addr);
          conn->principal_role = authorized.role;
          ssh_mem_copy(conn->principal, authorized.principal,
                       sizeof(conn->principal));
          ssh_mem_copy(conn->principal_fingerprint, authorized.fingerprint,
                       sizeof(conn->principal_fingerprint));
          ssh_log(SSH_LOG_INFO, "Public key auth success principal=%s role=%u\n",
                  conn->principal, (uint64_t)conn->principal_role);
          conn->state = SSH_STATE_AUTHENTICATED;
        } else {
          xaios_log("sshd: public key signature verification failed\n");
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (sshd_send_auth_failure(conn) != 0) return -1;
          ssh_log(SSH_LOG_WARN, "Public key auth failed (verify)\n");
        }
        return 0;
      }

      /* Unknown auth method */
      if (sshd_send_auth_failure(conn) != 0) return -1;
      return 0;
    }

    return 0;
  }

  if (conn->state == SSH_STATE_AUTHENTICATED ||
      conn->state == SSH_STATE_CHANNEL) {
    conn->state = SSH_STATE_CHANNEL;

    uint64_t packets_since_rekey =
        conn->crypto.encrypt_seq - conn->rekey_encrypt_base;
    uint64_t elapsed = now - conn->kex_start_time;
    if (packets_since_rekey >= 1048576U || elapsed >= SSHD_REKEY_INTERVAL) {
      return begin_server_rekey(conn, SSH_STATE_CHANNEL, now);
    }

    /* Check keepalive */
    if (now - conn->last_keepalive > SSHD_KEEPALIVE_INTERVAL) {
      uint8_t keepalive[32];
      keepalive[0] = SSH_MSG_GLOBAL_REQUEST;
      const char *ka_name = "keepalive@xaios.os";
      uint32_t ka_len = ssh_str_len(ka_name);
      ssh_write_u32_be(keepalive + 1, ka_len);
      ssh_mem_copy(keepalive + 5, ka_name, ka_len);
      keepalive[5 + ka_len] = 1;
      conn_packet_write_encrypted(conn, keepalive, 6 + ka_len);
      conn->last_keepalive = now;
      if (now - conn->last_activity > SSHD_TIMEOUT_IDLE) {
        ssh_log(SSH_LOG_WARN, "Idle timeout\n");
        return sshd_close_because("idle-timeout");
      }
    }

    /* Read one packet */
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return sshd_close_because("packet-read-failed");
    if (pkt->len == 0) return 0;

    conn->last_activity = now;
    uint8_t msg = pkt->data[0];

    if (msg == SSH_MSG_KEXINIT) {
      return begin_client_rekey(conn, pkt, SSH_STATE_CHANNEL, now);
    }

    if (msg == SSH_MSG_GLOBAL_REQUEST) {
      if (pkt->len < 6U) return -1;
      uint32_t request_len = ssh_read_u32_be(pkt->data + 1U);
      if (request_len > pkt->len - 6U) return -1;
      uint8_t want_reply = pkt->data[5U + request_len];
      if (want_reply != 0U) {
        uint8_t failure = SSH_MSG_REQUEST_FAILURE;
        if (conn_packet_write_encrypted(conn, &failure, 1U) != 0) return -1;
      }
      return 0;
    }

    if (msg >= 90 && msg <= 100) {
      if (ssh_channel_handle_packet(sockfd, pkt) != 0) return -1;
      return 0;
    }

    if (msg == SSH_MSG_DISCONNECT) {
      ssh_log(SSH_LOG_INFO, "Client disconnected\n");
      return sshd_close_because("client-disconnect");
    }

    /* Unknown message */
    return 0;
  }

  return 0;
}
