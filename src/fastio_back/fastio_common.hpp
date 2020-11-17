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

//
// Forward Private Searchable Symmetric Encryption with Optimized I/O Efficiency
//      
//      FASTIO - by Xiangfu Song
//      bintasong@gmail.com
//

#pragma once

#include <string>
#include <array>
#include <iostream>

#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
    namespace fastio {

        constexpr size_t kDerivationKeySize = 16;
        constexpr size_t kStateKeySize = 16;
        constexpr size_t kUpdateTokenSize = 8; // should be 8
        constexpr size_t kIndexSize = 8;
        
        typedef std::string search_token_type; 
        typedef std::string update_token_type;
        typedef std::string index_type;  // length should be 8!
        
        
        struct SearchRequest
        {
            search_token_type   token;  // state info
            std::string         derivation_key;
            uint32_t            add_count;
        };
        
        
        struct UpdateRequest
        {
            update_token_type   token;
            index_type          index;
        };
        
        void gen_update_token_masks(const std::string &deriv_key, 
                                    const std::string search_token,  // st
                                    update_token_type &update_token, // ut
                                    std::array<uint8_t, kUpdateTokenSize> &mask); // prf_{k}(st)
    }
}
