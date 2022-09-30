
#ifndef CHECKS_H
#define CHECKS_H

enum CheckType {
    CHECK_ALL,
    CHECK_LOCAL,
    CHECK_MAC_ADDRESS,
    CHECK_HOSTID,
    CHECK_MACHINEID,
    CHECK_HOSTNAME,
    CHECK_AWS_INSTANCE,
    CHECK_SCALEWAY_INSTANCE,
    CHECK_GITHUB_ACTION
};

int execute_check(CheckType ct, const char *id);
void display_dev_identifiers(CheckType ct);
#endif
