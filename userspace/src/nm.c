#include "nm.h"

static int nm_parse_uint(const char *s, unsigned int *out)
{
    unsigned int value = 0;

    if (!s || !*s || !out)
        return -1;

    while (*s) {
        unsigned int digit;
        if (*s < '0' || *s > '9')
            return -1;
        digit = (unsigned int)(*s - '0');
        if (value > (0xFFFFFFFFU - digit) / 10U)
            return -1;
        value = value * 10U + digit;
        s++;
    }

    *out = value;
    return 0;
}

static enum nm_cli_action nm_parse_action(long argc, char **argv,
                                           int *data_start_idx,
                                           int *is_whiteout)
{
    const char *c1;

    *data_start_idx = 2;
    if (argc < 2)
        return ACTION_NONE;

    c1 = argv[1];
    if (strcmp(c1, "rule") == 0 && argc >= 3) {
        const char *c2 = argv[2];
        *data_start_idx = 3;
        if (strcmp(c2, "add") == 0) return ACTION_RULE_ADD;
        if (strcmp(c2, "del") == 0) return ACTION_RULE_DEL;
        if (strcmp(c2, "list") == 0) return ACTION_RULE_LIST;
        if (strcmp(c2, "clear") == 0) return ACTION_RULE_CLEAR;
    }

    if (strcmp(c1, "uid") == 0 && argc >= 3) {
        const char *c2 = argv[2];
        *data_start_idx = 3;
        if (strcmp(c2, "add") == 0) return ACTION_UID_ADD;
        if (strcmp(c2, "del") == 0) return ACTION_UID_DEL;
        if (strcmp(c2, "list") == 0) return ACTION_UID_LIST;
        if (strcmp(c2, "clear") == 0) return ACTION_UID_CLEAR;
    }

    if (strcmp(c1, "clear") == 0) {
        if (argc >= 3 && strcmp(argv[2], "rules") == 0) {
            *data_start_idx = 3;
            return ACTION_RULE_CLEAR;
        }
        if (argc >= 3 && strcmp(argv[2], "uid") == 0) {
            *data_start_idx = 3;
            return ACTION_UID_CLEAR;
        }
        *data_start_idx = (argc >= 3) ? 3 : 2;
        return ACTION_CLEAR_ALL;
    }

    
    if (strcmp(c1, "add") == 0 || strcmp(c1, "a") == 0)
        return ACTION_RULE_ADD;
    if (strcmp(c1, "w") == 0 || strcmp(c1, "whiteout") == 0) {
        *is_whiteout = 1;
        return ACTION_RULE_ADD;
    }
    if (strcmp(c1, "del") == 0 || strcmp(c1, "d") == 0)
        return ACTION_RULE_DEL;
    if (strcmp(c1, "block") == 0 || strcmp(c1, "b") == 0)
        return ACTION_UID_ADD;
    if (strcmp(c1, "unblock") == 0 || strcmp(c1, "u") == 0)
        return ACTION_UID_DEL;
    if (strcmp(c1, "list") == 0 || strcmp(c1, "l") == 0) {
        if (argc >= 3 && strcmp(argv[2], "uid") == 0) {
            *data_start_idx = 3;
            return ACTION_UID_LIST;
        }
        return ACTION_RULE_LIST;
    }
    if (strcmp(c1, "version") == 0 || strcmp(c1, "v") == 0 ||
        strcmp(c1, "-v") == 0)
        return ACTION_VERSION;

    return ACTION_NONE;
}

static int nm_parse_options(long argc, char **argv, int data_start_idx,
                            const char **p_args, int *p_count,
                            unsigned int *target_uid, int *is_json,
                            int *is_whiteout)
{
    int count = 0;

    for (int i = data_start_idx; i < argc; i++) {
        if (strcmp(argv[i], "--uid") == 0) {
            if (i + 1 >= argc || nm_parse_uint(argv[++i], target_uid) < 0)
                return -1;
        } else if (strcmp(argv[i], "--json") == 0 ||
                   strcmp(argv[i], "json") == 0) {
            *is_json = 1;
        } else if (strcmp(argv[i], "--whiteout") == 0) {
            *is_whiteout = 1;
        } else {
            p_args[count++] = argv[i];
        }
    }

    *p_count = count;
    return 0;
}

static void nm_usage(void)
{
    print_str(
        "Usage: nm <command> <action> [args]\n"
        "  rule  add|del|list|clear  Manage rules\n"
        "  uid   add|del|list|clear  Manage UIDs\n"
        "  clear all                 Clear everything\n"
        "\n"
        "Examples:\n"
        "  nm rule add /data /mnt/x\n"
        "  nm rule list    |    nm uid add 10042\n"
        "  nm clear all\n");
}

static int nm_send_simple(struct nm_payload *payload, unsigned int cmd,
                          unsigned int uid)
{
    payload->cmd = cmd;
    payload->target_uid = uid;
    payload->arg1 = 0;
    payload->data_size = 0;
    return nm_send_payload(payload) < 0;
}

static int nm_send_rule_batch(struct nm_payload *payload,
                              enum nm_cli_action action, int is_whiteout,
                              unsigned int target_uid, const char **args,
                              int count)
{
    int step = (action == ACTION_RULE_ADD && !is_whiteout) ? 2 : 1;
    char *cwd_buf;
    const char *cwd;
    unsigned int cmd;
    int exit_code = 0;
    char *cursor;

    if (count < step)
        return 0;

    cwd_buf = (char *)payload - PATH_MAX;
    cwd = (sys3(SYS_GETCWD, (long)cwd_buf, PATH_MAX, 0) > 0) ? cwd_buf : "/";
    cmd = (action == ACTION_RULE_DEL) ? NM_CMD_DEL_RULE : NM_CMD_ADD_RULE;
    cursor = payload->buffer;
    payload->cmd = cmd;
    payload->arg1 = 0;
    payload->data_size = 0;

    for (int i = 0; i + step - 1 < count; i += step) {
        char *v_resolved = cwd_buf - PATH_MAX;
        char *r_resolved = v_resolved - PATH_MAX;
        char *v_end;
        int v_len;
        int r_len = 0;
        unsigned long record_size;

        v_end = resolve_path(v_resolved, PATH_MAX, cwd, args[i]);
        if (!v_end) {
            exit_code = 1;
            continue;
        }
        v_len = v_end - v_resolved;
        if (!v_len) {
            exit_code = 3;
            continue;
        }

        if (action == ACTION_RULE_ADD && !is_whiteout) {
            char *r_end = resolve_path(r_resolved, PATH_MAX, cwd, args[i + 1]);
            if (!r_end) {
                exit_code = 1;
                continue;
            }
            r_len = r_end - r_resolved;
            if (!r_len) {
                exit_code = 3;
                continue;
            }
        }

        record_size = (cmd == NM_CMD_ADD_RULE ? sizeof(struct nm_rule_hdr) : sizeof(struct nm_del_hdr)) +
                      (unsigned long)v_len + (unsigned long)r_len;
        if (record_size > sizeof(payload->buffer)) {
            exit_code = 1;
            continue;
        }
        if ((unsigned long)(cursor - payload->buffer) + record_size > sizeof(payload->buffer)) {
            payload->data_size = cursor - payload->buffer;
            exit_code |= (nm_send_payload(payload) < 0);
            cursor = payload->buffer;
            payload->cmd = cmd;
            payload->arg1 = 0;
        }

        if (cmd == NM_CMD_ADD_RULE) {
            struct nm_rule_hdr *h = (void *)cursor;
            h->flags = is_whiteout ? NM_FLAG_WHITEOUT : 0;
            h->uid = target_uid;
            h->v_len = v_len;
            h->r_len = r_len;
            memcpy(cursor + sizeof(*h), v_resolved, v_len);
            if (r_len)
                memcpy(cursor + sizeof(*h) + v_len, r_resolved, r_len);
            cursor += sizeof(*h) + v_len + r_len;
        } else {
            struct nm_del_hdr *h = (void *)cursor;
            h->uid = target_uid;
            h->v_len = v_len;
            memcpy(cursor + sizeof(*h), v_resolved, v_len);
            cursor += sizeof(*h) + v_len;
        }
    }

    if (cursor > payload->buffer) {
        payload->data_size = cursor - payload->buffer;
        exit_code |= (nm_send_payload(payload) < 0);
    }
    return exit_code;
}

static void nm_print_json_string(const char *s, unsigned long len)
{
    for (unsigned long i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '\\': print_str("\\\\"); break;
        case '"':  print_str("\\\""); break;
        case '\n': print_str("\\n"); break;
        case '\r': print_str("\\r"); break;
        case '\t': print_str("\\t"); break;
        default:
            if (c < 0x20)
                print_str("?");
            else
                sys3(SYS_WRITE, 1, (long)&s[i], 1);
            break;
        }
    }
}

static void nm_print_rule_record(const struct nm_rule_hdr *h,
                                 const char *v, const char *r,
                                 int is_json, int *has_output)
{
    int is_whiteout = (h->flags & NM_FLAG_WHITEOUT) != 0;
    int is_virtual_dir = (h->flags & NM_FLAG_VIRTUAL_DIR) != 0;

    if (is_json) {
        if (*has_output)
            print_str(",\n");
        print_str("  {\n    \"virtual\": \"");
        nm_print_json_string(v, h->v_len);
        if (is_whiteout)
            print_str("\",\n    \"whiteout\": true");
        else if (is_virtual_dir)
            print_str("\",\n    \"virtual_dir\": true");
        else {
            print_str("\",\n    \"real\": \"");
            nm_print_json_string(r, h->r_len);
            print_str("\"");
        }
        if (h->uid)
            { print_str(",\n    \"uid\": "); print_uint(h->uid); }
        print_str("\n  }");
    } else {
        print_strn(v, h->v_len);
        if (is_whiteout)
            print_str(" (whiteout)");
        else if (is_virtual_dir)
            print_str(" (virtual dir)");
        else {
            print_str(" -> ");
            print_strn(r, h->r_len);
        }
        if (h->uid) {
            print_str(" [UID: ");
            print_uint(h->uid);
            print_str("]");
        }
        print_str("\n");
    }
    *has_output = 1;
}

static int nm_list(struct nm_payload *payload, int is_uids, int is_json)
{
    int has_output = 0;
    int cmd = is_uids ? NM_CMD_GET_UIDS : NM_CMD_GET_LIST;

    if (is_uids)
        is_json = 1;
    if (is_json)
        print_str("[\n");

    payload->cmd = cmd;
    payload->arg1 = 0;
    payload->data_size = 0;

    while (1) {
        char *data;
        int pos = 0;

        if (nm_send_payload(payload) < 0 || payload->data_size == 0)
            break;
        data = payload->buffer;

        while (pos < (int)payload->data_size) {
            if (is_uids) {
                unsigned int uid = *(unsigned int *)(data + pos);
                pos += sizeof(uid);
                if (has_output)
                    print_str(",\n");
                print_str("  ");
                print_uint(uid);
                has_output = 1;
                continue;
            }

            {
                struct nm_rule_hdr *h = (void *)(data + pos);
                char *v;
                char *r;
                pos += sizeof(*h);
                v = data + pos;
                pos += h->v_len;
                r = data + pos;
                pos += h->r_len;
                nm_print_rule_record(h, v, r, is_json, &has_output);
            }
        }
        payload->cmd = cmd;
    }

    if (is_json)
        print_str("\n]\n");
    return 0;
}

static int nm_run(long *sp, long argc, char **argv)
{
    struct nm_payload *payload = (void *)(((long)sp - 1048576) & ~4095L);
    const char *p_args[argc > 0 ? argc : 1];
    enum nm_cli_action action;
    unsigned int target_uid = 0;
    int data_start_idx = 2;
    int p_count = 0;
    int is_json = 0;
    int is_whiteout = 0;

    action = nm_parse_action(argc, argv, &data_start_idx, &is_whiteout);
    if (nm_parse_options(argc, argv, data_start_idx, p_args, &p_count,
                         &target_uid, &is_json, &is_whiteout) < 0)
        return 1;

    switch (action) {
    case ACTION_RULE_ADD:
    case ACTION_RULE_DEL:
        return nm_send_rule_batch(payload, action, is_whiteout,
                                  target_uid, p_args, p_count);

    case ACTION_UID_ADD:
    case ACTION_UID_DEL: {
        unsigned int uid;
        if (p_count < 1 || nm_parse_uint(p_args[0], &uid) < 0)
            return 1;
        return nm_send_simple(payload,
                              action == ACTION_UID_ADD ? NM_CMD_ADD_UID : NM_CMD_DEL_UID,
                              uid);
    }

    case ACTION_CLEAR_ALL:
        return nm_send_simple(payload, NM_CMD_CLEAR_ALL, 0);

    case ACTION_RULE_CLEAR:
        return nm_send_simple(payload, NM_CMD_CLEAR_RULES, 0);

    case ACTION_UID_CLEAR:
        return nm_send_simple(payload, NM_CMD_CLEAR_UIDS, 0);

    case ACTION_VERSION:
        payload->cmd = NM_CMD_GET_VERSION;
        payload->target_uid = 0;
        payload->arg1 = 0;
        payload->data_size = sizeof(payload->buffer);
        if (nm_send_payload(payload) >= 0) {
            print_strn(payload->buffer, payload->data_size);
            print_str("\n");
            return 0;
        }
        return 1;

    case ACTION_RULE_LIST:
        return nm_list(payload, 0, is_json);

    case ACTION_UID_LIST:
        return nm_list(payload, 1, is_json);

    case ACTION_NONE:
    default:
        nm_usage();
        return 1;
    }
}

/* --- MAIN --- */
__attribute__((noreturn, used))
void c_main(long *sp)
{
    long argc = *sp;
    char **argv = (char **)(sp + 1);
    int exit_code = nm_run(sp, argc, argv);

    sys1(SYS_EXIT, exit_code);
    __builtin_unreachable();
}
