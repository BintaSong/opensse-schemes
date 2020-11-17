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

#include "fastio_common.hpp"
#include "utils/rocksdb_wrapper.hpp"

#include <string>
#include <array>
#include <fstream>
#include <functional>
#include <mutex>

#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
    namespace fastio {
        
        
        
        class FastioClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;

            static std::unique_ptr<FastioClient> construct_from_directory(const std::string& dir_path);
            static std::unique_ptr<FastioClient> init_in_directory(const std::string& dir_path, uint32_t n_keywords);
            
            FastioClient(const std::string& se_map_path, const std::string& up_map_path, const std::string& derivation_master_key, const std::string& state_master_key);
            FastioClient(const std::string& se_map_path, const std::string& up_map_path, const size_t tm_setup_size);

            ~FastioClient();
            
            size_t keyword_count() const;

            const std::string master_derivation_key() const;
            const std::string state_derivation_key() const; 
            
            void write_keys(const std::string& dir_path) const;

            bool gen_state(const std::string keyword, std::string& state);
            // bool get_increase_update(const std::string keyword, uint32_t &se_counter);
            
            SearchRequest   search_request(const std::string &keyword);
            UpdateRequest   update_request(const std::string &keyword, const index_type index);
            
            std::ostream& print_stats(std::ostream& out) const;
            
            const crypto::Prf<kDerivationKeySize>& derivation_prf() const;
            const crypto::Prf<kStateKeySize>& state_prf() const;

            static const std::string derivation_key_file__;
            static const std::string state_key_file__;
            
        private:
            static const std::string se_counter_map_file__;
            static const std::string up_counter_map_file__; 
            
            crypto::Prf<kDerivationKeySize> k_prf_;
            crypto::Prf<kStateKeySize> s_prf_;
            
            std::string get_keyword_index(const std::string &kw) const;
                      
            sophos::RocksDBCounter se_counter_map_;
            sophos::RocksDBCounter up_counter_map_;
            std::mutex token_map_mtx_;
            
        };
    } // namespace fastio
} // namespace sse