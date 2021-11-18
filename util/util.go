package util

func Remove0xPrefix(s string) string {
	if len(s) > 1 {
		if s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
			return s[2:]
		}
	}
	return s
}
