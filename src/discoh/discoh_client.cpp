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


#include "discoh_client.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
    namespace discoh {

        const std::string DiscohClient::derivation_key_file__ = "derivation_master.key";
        
        const std::string DiscohClient::global_counter_file__ = "global_counter.dat";

        std::unique_ptr<DiscohClient> DiscohClient::construct_from_directory(const std::string& dir_path)
        {
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string global_counter_path = dir_path + "/" + global_counter_file__;

            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }
            if (!is_file(global_counter_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing global counter data");
            }
            
            std::ifstream master_key_in(master_key_path.c_str());
            std::ifstream global_counter_in(global_counter_path.c_str());
            std::stringstream master_key_buf, global_counter_buf;
            
            master_key_buf << master_key_in.rdbuf();
            global_counter_buf << global_counter_in.rdbuf();
                        
            return std::unique_ptr<DiscohClient>(new  DiscohClient(master_key_buf.str(), dir_path, std::stoi(global_counter_buf.str())));
        }
        
        std::unique_ptr<DiscohClient> DiscohClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        {
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
                        
            auto c_ptr =  std::unique_ptr<DiscohClient>(new DiscohClient(n_keywords, dir_path)); 
            
            c_ptr->write_keys(dir_path);
            
            return c_ptr;
        }
        
        DiscohClient::DiscohClient(const size_t tm_setup_size, const std::string& dir_path) :
        k_prf_(), local_counter_map(), main_directory_path(dir_path), shared_global_counter(-1)
        {
        }
        
        DiscohClient::DiscohClient(const std::string& derivation_master_key, const std::string& dir_path, const uint32_t counter) :
        k_prf_(derivation_master_key), local_counter_map(), main_directory_path(dir_path), shared_global_counter(counter)
        {
        }
        
        DiscohClient::DiscohClient(const std::string& derivation_master_key, const size_t tm_setup_size, const std::string& dir_path, const uint32_t counter) :
        k_prf_(derivation_master_key), local_counter_map(), main_directory_path(dir_path), shared_global_counter(counter)
        {
        }
        
        DiscohClient::~DiscohClient()
        {
            // const std::string SophosClient::global_counter_file__;
            std::string global_counter_path = main_directory_path + "/" + global_counter_file__;
            std::ofstream counter_out(global_counter_path.c_str());
            if (!counter_out.is_open()) {
                throw std::runtime_error(global_counter_path + ": unable to write the global counter file.");
            }
            
            counter_out << shared_global_counter; // store global counter into file
            counter_out.close();       
        }
        
//        size_t SophosClient::keyword_count() const
//        {
//            return counter_map_.approximate_size();
//        }
        
        const std::string DiscohClient::master_derivation_key() const
        {
            return std::string(k_prf_.key().begin(), k_prf_.key().end());
        }
        
        const crypto::Prf<kDerivationKeySize>& DiscohClient::derivation_prf() const
        {
            return k_prf_;
        }

        const uint32_t DiscohClient::hashchain_size() const 
        {
            return HashChainSize;
        }
        
        const uint32_t DiscohClient::get_global_counter() const 
        {
            return shared_global_counter;
        }

        std::string DiscohClient::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            return hash_string.erase(kKeywordIndexSize);
        }
        
        std::string DiscohClient::gen_search_token(const std::string &kw_seed, const uint32_t global_counter) const
        {
            auto st = k_prf_.prf_string(kw_seed + "search_token");
            for (size_t i = HashChainSize; i > global_counter; i--) 
            {
                st = crypto::Hash::hash(st);
            }
            return st;
        }

        SearchRequest DiscohClient::search_request(const std::string &keyword) const
        {
            SearchRequest req;
            req.add_count = 0;
            
            std::string seed = get_keyword_index(keyword);
            logger::log(logger::DBG) << "seed: " << hex_string(seed) << std::endl;

            uint32_t global_counter = get_global_counter();

            req.token = gen_search_token(seed, global_counter);              
            req.derivation_key = derivation_prf().prf_string(seed);
            req.add_count = shared_global_counter+1;
            
            return req;
        }
        
        
        UpdateRequest  DiscohClient::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest req;
            search_token_type st; 
            
            uint32_t global_counter, local_counter; 
            global_counter = get_global_counter();
            get_and_increase_local_counter(keyword, local_counter);

            // get (and possibly construct) the keyword index
            std::string seed = get_keyword_index(keyword);

            std::string deriv_key = derivation_prf().prf_string(seed);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derivation key: " << hex_string(deriv_key) << std::endl;
            }
            
            if (local_counter == 0) {
                st = gen_search_token(seed, global_counter);
                cache_search_token(keyword, st);
            }
            else {
                bool success = get_cached_search_token(keyword, st);
                if (!success) {
                    st = gen_search_token(seed, global_counter);
                    cache_search_token(keyword, st);
                }
            }

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "ST: " << hex_string(st) << std::endl;
            }        
            
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            gen_update_token_masks(deriv_key, st, local_counter, req.token, mask);
            req.index = xor_mask(index, mask);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
        
        
        /*
        std::ostream& SophosClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
            
            return out;
        }
        */
        
        void DiscohClient::write_keys(const std::string& dir_path) const
        {
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            
            std::ofstream master_key_out(master_key_path.c_str());
            if (!master_key_out.is_open()) {
                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
            }
            
            master_key_out << master_derivation_key();
            master_key_out.close();
        }

        const void DiscohClient::increase_global_counter() const // MUST call this function before batch update!
        {
            int *point = (int*) &shared_global_counter;
            *point = shared_global_counter + 1; 
            //shared_global_counter = shared_global_counter + 1; // FIXME: wrong usecase
        }

        // maintaining local counter for level-2 index during update, no need to store in file after execution.
        uint32_t DiscohClient::get_and_increase_local_counter(const std::string &keyword, uint32_t &keyword_local_counter)
        {
            std::unique_lock<std::mutex> lock(local_counter_map_mtx_);

            auto  it = local_counter_map.find(keyword); 
            if(it != local_counter_map.end()) {
                keyword_local_counter = it->second + 1;
            }
            else{
                 keyword_local_counter = 0; 
            }
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "keyword: (" << keyword << ", " << keyword_local_counter << ")" << std::endl;
            }
            local_counter_map[keyword] = keyword_local_counter; 
        } 

        bool DiscohClient::get_cached_search_token(const std::string &keyword, search_token_type& search_token)
        {
            //std::unique_lock<std::mutex> lock(keyword_search_token_map_mtx_);

            auto  it = keyword_search_token_map.find(keyword); 

            if(it != keyword_search_token_map.end()) {
                search_token =  it->second;
            }
            else{
                logger::log(logger::ERROR) << "We are supposed to find the cached search token!" << std::endl; 
                return false;
            }
            return true; 
        }

        void DiscohClient::cache_search_token(const std::string &keyword, search_token_type search_token)
        {
            std::unique_lock<std::mutex> lock(keyword_search_token_map_mtx_);
            keyword_search_token_map[keyword] = search_token; 
        }
    }
}
