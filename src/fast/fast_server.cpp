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
//      FAST - by Xiangfu Song
//      bintasong@gmail.com
//

#include "fast_server.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
namespace fast {
    

FastServer::FastServer(const std::string& db_path) :
edb_(db_path)
{
    
}

FastServer::FastServer(const std::string& db_path, const size_t tm_setup_size) :
    edb_(db_path)
{
    
}


std::list<index_type> FastServer::search(const SearchRequest& req)
{
    std::list<index_type> results;
    
    search_token_type st = req.token;

    if (logger::severity() <= logger::DBG) {

        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }
    
    for (size_t i = 0; i < req.add_count; i++) {
        // std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        // search_token_type pre_st;
        update_token_type ut;
        std::array<uint8_t, kUpdateTokenSize> mask;

              

        gen_update_token_masks(req.derivation_key, st, ut, mask);
        
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
        }

        bool found = edb_.get(ut, r);
        
        if (found) {          
            r = xor_mask(r, mask);
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << hex_string(r) << std::endl;
            }
            index_type index = r.substr(0, 8); // r[0...7]

            results.push_back( (index) );
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "index: " << hex_string(index)  << std::endl;
            }
            st = r.substr(8, 16);       // r[8...24]
            // logger::log(logger::INFO) << "ST: " << hex_string(st) << std::endl; 
        }else{
            logger::log(logger::ERROR) << "sync, i = "<< i << ", We were supposed to find something!" << std::endl;        }
    }
    
    return results;
}

    void FastServer::search_callback(const SearchRequest& req, std::function<void(index_type)> post_callback)
    {
        std::list<index_type> results;

        search_token_type st = req.token;

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
        
            logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
        }
            
        for (size_t i = 0; i < req.add_count; i++) {
            // std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
            index_type r;
            update_token_type ut;
            std::array<uint8_t, kUpdateTokenSize> mask;

            logger::log(logger::DBG) << "ST: " << hex_string(st) << std::endl;

            gen_update_token_masks(req.derivation_key, st, ut, mask);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
            }
            
            bool found = edb_.get(ut,r);
            
            if (found) {              
                // parse r to get index and random_key
                r = xor_mask(r, mask);
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Found: " << hex_string(r)  << std::endl;
                }
                
                index_type index = r.substr(0, 8); // r[0...7]

                results.push_back(index);
                post_callback( (index) );
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "index: " << hex_string(index)  << std::endl;
                }
                // logger::log(logger::INFO) << "1-st: " << hex_string(r) << std::endl;

                st = r.substr(8, 16);       // r[8...r.size()] is previous state info  
            }else{
                logger::log(logger::ERROR) << "async, i = "<< i << ", We were supposed to find something!" << std::endl;
            }
        }
    }
    

// std::list<index_type> FastServer::search_parallel_full(const SearchRequest& req)
// {
//     std::list<index_type> results;
    
//     search_token_type st = req.token;
    
//     auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

//     if (logger::severity() <= logger::DBG) {
//         logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
//         logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
//     }

//     // ThreadPool prf_pool(1);
//     ThreadPool token_map_pool(1);
//     ThreadPool decrypt_pool(1);

//     auto decrypt_job = [&derivation_prf, &results](const index_type r, const std::string& st_string)
//     {
//         index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
//         results.push_back(v);
//     };

//     auto lookup_job = [&derivation_prf, &decrypt_pool, &decrypt_job, this](const std::string& st_string, const update_token_type& token)
//     {
//         index_type r;
        
//         if (logger::severity() <= logger::DBG) {
//             logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
//         }
        
//         bool found = edb_.get(token,r);
        
//         if (found) {
//             if (logger::severity() <= logger::DBG) {
//                 logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
//             }
            
//             decrypt_pool.enqueue(decrypt_job, r, st_string);

//         }else{
//             logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
//         }

//     };

//     for (uint8_t i = 0; i < req.add_count; i++) {

//         update_token_type ut = derivation_prf.prf_string(req.token + '0').erase(kUpdateTokenSize - kIndexSize);
        
//         token_map_pool.enqueue(lookup_job, req.token, ut);
//     }

//     decrypt_pool.join();
//     token_map_pool.join();
    
//     return results;
// }

void FastServer::update(const UpdateRequest& req)
{
    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Update: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
    }

//    edb_.add(req.token, req.index);
    edb_.put(req.token, req.index);
}

std::ostream& FastServer::print_stats(std::ostream& out) const
{
//    out << "Number of tokens: " << edb_.size();
//    out << "; Load: " << edb_.load();
//    out << "; Overflow bucket size: " << edb_.overflow_size() << std::endl;
    
    return out;
}

} // namespace fast
} // namespace sse
