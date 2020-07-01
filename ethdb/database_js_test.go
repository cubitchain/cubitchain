// Copyright 2014 The qbc Authors
// This file is part of the qbc library.
//
// The qbc library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The qbc library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the qbc library. If not, see <http://www.gnu.org/licenses/>.

// +build js

package ethdb_test

import (
	"github.com/cubitchain/cubitchain/ethdb"
)

var _ ethdb.Database = &ethdb.LDBDatabase{}
