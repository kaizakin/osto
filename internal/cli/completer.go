package cli

import (
	"github.com/chzyer/readline"
	"github.com/kaizakin/osto/internal/models"
)

var preLoginCommands = []string{"register", "login", "help", "exit"}
var postLoginCommands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help"}

// DynamicCompleter switches tab-completion based on login state.
type DynamicCompleter struct {
	State *models.AppState
}

func (d *DynamicCompleter) Do(line []rune, pos int) ([][]rune, int) {
	cmds := preLoginCommands
	if d.State.IsLoggedIn() {
		cmds = postLoginCommands
	}
	prefix := string(line[:pos])
	var matches [][]rune
	for _, cmd := range cmds {
		if len(cmd) >= len(prefix) && cmd[:len(prefix)] == prefix {
			matches = append(matches, []rune(cmd[len(prefix):]))
		}
	}
	return matches, len(prefix)
}

var _ readline.AutoCompleter = (*DynamicCompleter)(nil)
