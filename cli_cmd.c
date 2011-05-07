#include <string.h>
#include <assert.h>

#include "libcli_wrapper.h"
#include "elog.h"

/*
 * Rows below are a special case; longer than 80 lines for readability.
 *
 * Note: Aliases can be added by simply adding several lines below that use the
 * same callback fcn. Example: mymodule_status, mymodulestatus. Remember, tab
 * completion is most convenient if you do not have to write underscores, so
 * try to always provide a command alias without underscores.
 *
 */

struct CliCmdSpec cli_cmds_mymodule[] = {
    {0}
};

struct CliCmdSpec *cli_get_commands(void)
{
    return &cli_cmds_mymodule[0];
}

const char *cli_get_banner(void)
{
    return NULL;
}

const char *cli_get_hostname(void)
{
    return NULL;
}
