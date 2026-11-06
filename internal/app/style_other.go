// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build !windows

package app

import "os"

// enableColor has nothing to switch on outside Windows: a terminal that passed
// the TERM checks takes escape codes as they are.
func enableColor(*os.File) (bool, func()) { return true, func() {} }
