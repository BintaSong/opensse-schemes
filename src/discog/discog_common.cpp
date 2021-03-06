//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//

#include "discog_common.hpp"

#include <sse/crypto/block_hash.hpp>

#include <cstring>

namespace sse {
    namespace discog {
        
        void gen_update_token_mask(const uint8_t* search_token, update_token_type &update_token, const size_t mask_len, uint8_t *mask)
        {
            crypto::Prg prg(search_token);
            
            prg.derive(0,kUpdateTokenSize, update_token.data());
            prg.derive(kUpdateTokenSize, mask_len, mask);
        }

    }
}
