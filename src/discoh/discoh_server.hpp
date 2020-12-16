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

#include "discoh_common.hpp"
#include "utils/rocksdb_wrapper.hpp"

#include <string>
#include <array>
#include <fstream>
#include <functional>

#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
namespace discoh {

    class DiscohServer {
    public:
               
        DiscohServer(const std::string& db_path, const uint32_t& hashchain_size);
        DiscohServer(const std::string& db_path, const size_t tm_setup_size, const uint32_t& hashchain_size);
        
        const uint32_t hashchain_size() const;

        std::list<index_type> search(const SearchRequest& req);
        void search_callback(const SearchRequest& req, std::function<void(index_type)> post_callback);
        
        //std::list<index_type> search_parallel_full(const SearchRequest& req);
        //std::list<index_type> search_parallel(const SearchRequest& req, uint8_t access_threads);
        //std::list<index_type> search_parallel_light(const SearchRequest& req, uint8_t thread_count);

        //void search_parallel_callback(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t rsa_thread_count, uint8_t access_thread_count, uint8_t post_thread_count);
        //void search_parallel_light_callback(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t thread_count);

        void update(const UpdateRequest& req);
        
        std::ostream& print_stats(std::ostream& out) const;
        void flush_edb();
    private:
        sophos::RockDBWrapper edb_;
        
        uint32_t hashchain_size_;
    };

} // namespace discoh
} // namespace sse
