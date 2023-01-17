// Copyright (c) 2023 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License.AGPL.txt in the project root for license information.

package cmd

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gitpod-io/gitpod/common-go/log"
	"github.com/spf13/cobra"
)

var debugEnvCmd = &cobra.Command{
	Use: "debug-env",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO supervisor - hardcode for now, but how to separate from workspace envs? how to access them?
		// TODO are there any other env vars which are not picked up by supervisor, but has to propagated from ws-manager to support docker or something?
		initEnvs, err := ioutil.ReadFile("/proc/1/environ")
		if err != nil {
			log.Fatal(err)
		}
		initEnviron := strings.Split(string(initEnvs), "\x00")
		for _, env := range initEnviron {
			if env == "" {
				continue
			}
			parts := strings.SplitN(env, "=", 2)
			key := parts[0]
			if strings.HasPrefix(key, "THEIA_") ||
				strings.HasPrefix(key, "GITPOD_") ||
				// TODO IDE - get rid of env vars in images, use supervisor api as a mediator to support many IDEs running in the same worksapce?
				// TODO PATH - use well defined locations to pick up binaries, i.e. /ide/bin or /ide-desktop/bin in supervisor?
				key == "VSX_REGISTRY_URL" ||
				key == "EDITOR" ||
				key == "VISUAL" ||
				key == "GP_OPEN_EDITOR" ||
				key == "GIT_EDITOR" ||
				key == "GP_PREVIEW_BROWSER" ||
				key == "GP_EXTERNAL_BROWSER" ||
				key == "JETBRAINS_BACKEND_QUALIFIER" {
				fmt.Println(env)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(debugEnvCmd)
}
