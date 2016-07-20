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


#pragma once

#include "token_tree.hpp"

namespace sse {
    namespace diane {

        constexpr size_t kSearchTokenKeySize = TokenTree::kTokenSize;
        constexpr size_t kUpdateTokenSize = 16;
        constexpr size_t kKeywordTokenSize = 32;

        typedef TokenTree::token_type search_token_key_type;
        typedef std::array<uint8_t, kKeywordTokenSize> keyword_token_type;
        typedef std::array<uint8_t, kUpdateTokenSize> update_token_type;
        typedef uint64_t index_type;
        
        typedef  std::list<std::pair<TokenTree::token_type, uint8_t>>  search_token_type;
                
        struct SearchRequest
        {
            std::list<std::pair<search_token_key_type, uint8_t>>  token_list;
            uint32_t                add_count;
            keyword_token_type      kw_token;
        };
        
        struct UpdateRequest
        {
            update_token_type   token;
            index_type          index;
        };

    }
}