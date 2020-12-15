//
//  sophos_common.cpp
//  SSE_Schemes
//
//  Created by Raphael Bost on 04/10/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include "discoh_common.hpp"


#include <sse/crypto/prf.hpp>

#include <cstring>

namespace sse {
    namespace discoh {
        
        void gen_update_token_masks(const std::string &deriv_key,
                                    search_token_type &search_token,
                                    const uint32_t local_counter,
                                    update_token_type &update_token,
                                    std::array<uint8_t, kUpdateTokenSize> &mask)
        {
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);

            //std::string st_string(reinterpret_cast<const char*>(search_token), kSearchTokenSize);
            
            update_token = derivation_prf.prf_string(search_token + std::to_string(local_counter) + '0');
            mask = derivation_prf.prf(search_token + std::to_string(local_counter) + '1');
        }
    }
}
