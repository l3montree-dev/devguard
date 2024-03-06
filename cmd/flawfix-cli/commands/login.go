// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package commands

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/spf13/cobra"
)

func open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func LoginCommand() *cobra.Command {
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login to flawfix",
		Long:  `Login to flawfix. It will save your credentials in your home directory. Those credentials are not encrypted!`,
		Run: func(cmd *cobra.Command, args []string) {
			// start a webserver on port 6060
			syncChan := make(chan struct{})
			go func() {
				http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					// there is now a cookie - use it to detect the session
					sessionCookie, err := r.Cookie("ory_kratos_session")

					if err != nil {
						http.Error(w, "not logged in", http.StatusUnauthorized)
						return
					}

					authClient := auth.GetOryApiClient(os.Getenv("ORY_KRATOS"))
					session, _, err := authClient.FrontendApi.ToSession(
						r.Context(),
					).Cookie(sessionCookie.Value).Execute()

					if err != nil {
						fmt.Println(err)
						http.Error(w, "not logged in", http.StatusUnauthorized)
						return
					}

					fmt.Println(session)
					w.Write([]byte("logged in")) // nolint: errcheck
					close(syncChan)
				})

				err := http.ListenAndServe(":6060", nil) // nolint
				if err != nil {
					panic(err)
				}
			}()
			err := open("http://localhost:3000/login?return_to=http://localhost:6060")
			if err != nil {
				panic(err)
			}
			<-syncChan
		},
	}
	return loginCmd
}
