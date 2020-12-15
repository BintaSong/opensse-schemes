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


#include "discot_client.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
    namespace discot {
        
        const std::string DiscotClient::tdp_sk_file__ = "tdp_sk.key";
        const std::string DiscotClient::derivation_key_file__ = "derivation_master.key";
        
        
        const std::string DiscotClient::rsa_prg_key_file__ = "rsa_prg.key";
        // const std::string SophosClient::counter_map_file__ = "counters.dat";
        const std::string DiscotClient::global_counter_file__ = "global_counter.dat";
        
        // uint32_t DiscotClient::shared_global_counter;
        // std::string DiscotClient::main_directory_path;

        std::unique_ptr<DiscotClient> DiscotClient::construct_from_directory(const std::string& dir_path)
        {
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            // main_directory_path = dir_path;
            std::string sk_path = dir_path + "/" + tdp_sk_file__;
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            // std::string counter_map_path = dir_path + "/" + counter_map_file__;
            std::string global_counter_path = dir_path + "/" + global_counter_file__;
            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;
            
            if (!is_file(sk_path)) {
                // error, the secret key file is not there
                throw std::runtime_error("Missing secret key file");
            }
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }
            if (!is_file(rsa_prg_key_path)) {
                // error, the rsa prg key file is not there
                throw std::runtime_error("Missing rsa prg key file");
            }
            //if (!is_directory(counter_map_path)) {
                // error, the token map data is not there
            //    throw std::runtime_error("Missing token data");
            // }
            if (!is_file(global_counter_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing global counter data");
            }
            
            std::ifstream sk_in(sk_path.c_str());
            std::ifstream master_key_in(master_key_path.c_str());
            std::ifstream rsa_prg_key_in(rsa_prg_key_path.c_str());
            std::ifstream global_counter_in(global_counter_path.c_str());
            std::stringstream sk_buf, master_key_buf, rsa_prg_key_buf, global_counter_buf;
            
            sk_buf << sk_in.rdbuf();
            master_key_buf << master_key_in.rdbuf();
            rsa_prg_key_buf << rsa_prg_key_in.rdbuf();
            global_counter_buf << global_counter_in.rdbuf();
                        
            return std::unique_ptr<DiscotClient>(new  DiscotClient(sk_buf.str(), master_key_buf.str(), rsa_prg_key_buf.str(), dir_path, std::stoi(global_counter_buf.str())));
        }
        
        std::unique_ptr<DiscotClient> DiscotClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        {
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            // std::string counter_map_path = dir_path + "/" + counter_map_file__;
            
            auto c_ptr =  std::unique_ptr<DiscotClient>(new DiscotClient(n_keywords, dir_path)); 
            
            c_ptr->write_keys(dir_path);
            
            // the initial global counter 
            // shared_global_counter = -1; 

            return c_ptr;
        }
        
        DiscotClient::DiscotClient(const size_t tm_setup_size, const std::string& dir_path) :
        k_prf_(), inverse_tdp_(), rsa_prg_(), local_counter_map(), main_directory_path(dir_path), shared_global_counter(-1)
        {
        }
        
        DiscotClient::DiscotClient(const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const std::string& dir_path, const uint32_t counter) :
        k_prf_(derivation_master_key), inverse_tdp_(tdp_private_key), rsa_prg_(rsa_prg_key), local_counter_map(), main_directory_path(dir_path), shared_global_counter(counter)
        {
        }
        
        DiscotClient::DiscotClient(const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const size_t tm_setup_size, const std::string& dir_path, const uint32_t counter) :
        k_prf_(derivation_master_key), inverse_tdp_(tdp_private_key), rsa_prg_(rsa_prg_key), local_counter_map(), main_directory_path(dir_path), shared_global_counter(counter)
        {
        }
        
        DiscotClient::~DiscotClient()
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
        
        const std::string DiscotClient::public_key() const
        {
            return inverse_tdp_.public_key();
        }
        
        const std::string DiscotClient::private_key() const
        {
            return inverse_tdp_.private_key();
        }
        
        const std::string DiscotClient::master_derivation_key() const
        {
            return std::string(k_prf_.key().begin(), k_prf_.key().end());
        }
        
        const crypto::Prf<kDerivationKeySize>& DiscotClient::derivation_prf() const
        {
            return k_prf_;
        }
        const sse::crypto::TdpInverse& DiscotClient::inverse_tdp() const
        {
            return inverse_tdp_;
        }
        
        const uint32_t DiscotClient::get_global_counter() const 
        {
            return shared_global_counter;
        }

        std::string DiscotClient::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            return hash_string.erase(kKeywordIndexSize);
        }
        
        SearchRequest   DiscotClient::search_request(const std::string &keyword) const
        {
            //uint32_t kw_counter;
            //bool found;
            SearchRequest req;
            req.add_count = 0;
            
            std::string seed = get_keyword_index(keyword);
            logger::log(logger::DBG) << "seed: " << hex_string(seed) << std::endl;
            //found = counter_map_.get(keyword, kw_counter);
            
            //if(!found)
            //{
            //    logger::log(logger::INFO) << "No matching counter found for keyword " << keyword << " (index " << hex_string(seed) << ")" << std::endl;
            //}else{
                // Now derive the original search token from the kw_index (as seed)
                req.token = inverse_tdp().generate_array(rsa_prg_, seed);
                req.token = inverse_tdp().invert_mult(req.token, shared_global_counter);
                                
                req.derivation_key = derivation_prf().prf_string(seed);
                req.add_count = shared_global_counter+1;
            //}
            
            return req;
        }
        
        
        UpdateRequest  DiscotClient::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest req;
            search_token_type st; 
            
            // get (and possibly construct) the keyword index
            std::string seed = get_keyword_index(keyword);
            
            // retrieve the counter
            //uint32_t kw_counter;
            
            //bool success = counter_map_.get_and_increment(keyword, kw_counter);
            
            //assert(success); 
            uint32_t local_counter; 
            get_and_increase_local_counter(keyword, local_counter);
            
            st = inverse_tdp().generate_array(rsa_prg_, seed);
            
            if (shared_global_counter==0) {
                logger::log(logger::DBG) << "ST0 " << hex_string(st) << std::endl;
            }else{
                st = inverse_tdp().invert_mult(st, shared_global_counter);
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
                }
            }
            
            
            std::string deriv_key = derivation_prf().prf_string(seed);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derivation key: " << hex_string(deriv_key) << std::endl;
            }
            
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            gen_update_token_masks(deriv_key, st.data(), local_counter, req.token, mask);
            req.index = xor_mask(index, mask);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
        
        std::string DiscotClient::rsa_prg_key() const
        {
            return std::string(rsa_prg_.key().begin(), rsa_prg_.key().end());
        }
        
        /*
        std::ostream& SophosClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
            
            return out;
        }
        */
        
        void DiscotClient::write_keys(const std::string& dir_path) const
        {
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string sk_path = dir_path + "/" + tdp_sk_file__;
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            
            std::ofstream sk_out(sk_path.c_str());
            if (!sk_out.is_open()) {
                throw std::runtime_error(sk_path + ": unable to write the secret key");
            }
            
            sk_out << private_key();
            sk_out.close();
            
            std::ofstream master_key_out(master_key_path.c_str());
            if (!master_key_out.is_open()) {
                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
            }
            
            master_key_out << master_derivation_key();
            master_key_out.close();
            
            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;
            
            std::ofstream rsa_prg_key_out(rsa_prg_key_path.c_str());
            if (!rsa_prg_key_out.is_open()) {
                throw std::runtime_error(rsa_prg_key_path + ": unable to write the rsa prg key");
            }
            
            rsa_prg_key_out << rsa_prg_key();
            rsa_prg_key_out.close();
        }

        const void DiscotClient::increase_global_counter() const // MUST call this function before batch update!
        {
            int *point = (int*) &shared_global_counter;
            *point = shared_global_counter + 1; 
            // shared_global_counter = shared_global_counter + 1; // FIXME: wrong usecase
        }

        // maintaining local counter for level-2 index during update, no need to store in file after execution.
        uint32_t DiscotClient::get_and_increase_local_counter(const std::string &keyword, uint32_t &keyword_local_counter)
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
    }
}
