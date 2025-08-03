// src/auth.c
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include "auth.h"

static struct pam_conv conv = {
    misc_conv,
    NULL};

int authenticate()
{
  pam_handle_t *pamh = NULL;
  int retval = pam_start("securepass", NULL, &conv, &pamh);
  // It loads the file: etc/pam.d/securePass to get authentication configuration details.

  if (retval == PAM_SUCCESS)
    retval = pam_authenticate(pamh, 0);

  if (retval == PAM_SUCCESS)
    retval = pam_acct_mgmt(pamh, 0);

  pam_end(pamh, retval);
  return retval == PAM_SUCCESS ? 1 : 0;
}