// src/auth.c
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include "auth.h"
#include "crypto.h" // Include the new header for declarations

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// Custom conversation function with added logging for diagnostics.
static int my_conv(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr)
{
    fprintf(stderr, "[CONV_LOG] my_conv called with num_msg = %d\n", num_msg);

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
        fprintf(stderr, "[CONV_LOG] Invalid num_msg. Returning PAM_CONV_ERR.\n");
        return PAM_CONV_ERR;
    }

    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (*resp == NULL) {
        fprintf(stderr, "[CONV_LOG] calloc failed. Returning PAM_BUF_ERR.\n");
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        fprintf(stderr, "[CONV_LOG] Processing message %d, style = %d\n", i, msg[i]->msg_style);
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF: // Used for passwords
            {
                fprintf(stderr, "[CONV_LOG] Got PAM_PROMPT_ECHO_OFF. Calling getpass().\n");
                char *password = getpass(msg[i]->msg);
                if (password == NULL) {
                    fprintf(stderr, "[CONV_LOG] getpass() failed. Returning PAM_CONV_ERR.\n");
                    for (int j = 0; j < i; j++) free((*resp)[j].resp);
                    free(*resp);
                    *resp = NULL;
                    return PAM_CONV_ERR;
                }
                (*resp)[i].resp = strdup(password);
                fprintf(stderr, "[CONV_LOG] getpass() succeeded.\n");
                break;
            }
            case PAM_PROMPT_ECHO_ON: // Used for usernames, etc.
            {
                fprintf(stderr, "[CONV_LOG] Got PAM_PROMPT_ECHO_ON. Not handled, returning error.\n");
                for (int j = 0; j < i; j++) free((*resp)[j].resp);
                free(*resp);
                *resp = NULL;
                return PAM_CONV_ERR;
            }
            case PAM_ERROR_MSG:
                fprintf(stderr, "[CONV_LOG] Got PAM_ERROR_MSG: %s\n", msg[i]->msg);
                break;
            case PAM_TEXT_INFO:
                fprintf(stderr, "[CONV_LOG] Got PAM_TEXT_INFO: %s\n", msg[i]->msg);
                break;
            default:
                fprintf(stderr, "[CONV_LOG] Got unknown message style (%d). Returning PAM_CONV_ERR.\n", msg[i]->msg_style);
                for (int j = 0; j < num_msg; j++) {
                    if ((*resp)[j].resp) {
                        free((*resp)[j].resp);
                    }
                }
                free(*resp);
                *resp = NULL;
                return PAM_CONV_ERR;
        }
    }

    fprintf(stderr, "[CONV_LOG] my_conv finished successfully.\n");
    return PAM_SUCCESS;
}

static struct pam_conv conv = {
    my_conv,
    NULL};

int authenticate()
{
  pam_handle_t *pamh = NULL;
  char *user = getenv("SUDO_USER");
  if (user == NULL) {
    user = getlogin();
  }
  fprintf(stderr, "[AUTH_LOG] Authenticating user: %s\n", user ? user : "NULL");

  int retval = pam_start("securepass", user, &conv, &pamh);
  fprintf(stderr, "[AUTH_LOG] pam_start returned: %d (%s)\n", retval, pam_strerror(pamh, retval));

  if (retval == PAM_SUCCESS) {
    retval = pam_authenticate(pamh, 0);
    fprintf(stderr, "[AUTH_LOG] pam_authenticate returned: %d (%s)\n", retval, pam_strerror(pamh, retval));
  }

  if (retval == PAM_SUCCESS) {
    retval = pam_acct_mgmt(pamh, 0);
    fprintf(stderr, "[AUTH_LOG] pam_acct_mgmt returned: %d (%s)\n", retval, pam_strerror(pamh, retval));
  }

  fprintf(stderr, "[AUTH_LOG] Final PAM retval: %d\n", retval);
  pam_end(pamh, retval);
  fprintf(stderr, "[AUTH_LOG] Returning status: %s\n", (retval == PAM_SUCCESS) ? "SUCCESS" : "FAILURE");
  return retval == PAM_SUCCESS ? 1 : 0;
}
