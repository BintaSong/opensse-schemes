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

#include "fastio_client.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
    namespace fastio {
        
        const std::string FastioClient::derivation_key_file__ = "derivation_master.key"; 
        const std::string FastioClient::state_key_file__ = "state_master.key";       
        const std::string FastioClient::se_counter_map_file__ = "search_counters.dat";
        const std::string FastioClient::up_counter_map_file__ = "update_counters.dat";
        
        std::unique_ptr<FastioClient> FastioClient::construct_from_directory(const std::string& dir_path)
        { // 如果存在该目录，密钥文件已经存在，执行初始化
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string state_key_path = dir_path + "/" + state_key_file__;
            std::string se_counter_map_path = dir_path + "/" + se_counter_map_file__;
            std::string up_counter_map_path = dir_path + "/" + up_counter_map_file__;
            
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }

            if (!is_file(state_key_path)) {
                // error, the state key file is not there
                throw std::runtime_error("Missing state derivation key file");
            }

            if (!is_directory(se_counter_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing search counter data");
            }

            if (!is_directory(up_counter_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing update counter data");
            }
            
            std::ifstream master_key_in(master_key_path.c_str()), state_key_in(state_key_path.c_str());
            std::stringstream master_key_buf, state_key_buf;

            master_key_buf << master_key_in.rdbuf();
            state_key_buf << state_key_in.rdbuf();

            return std::unique_ptr<FastioClient>(new FastioClient(se_counter_map_path, up_counter_map_path, master_key_buf.str(), state_key_buf.str() ));
        }
        
        std::unique_ptr<FastioClient> FastioClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        { // 在文件夹下执行初始化，文件夹中没有密钥文件
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string se_counter_map_path = dir_path + "/" + se_counter_map_file__;
            std::string up_counter_map_path = dir_path + "/" + up_counter_map_file__;
            
            auto c_ptr =  std::unique_ptr<FastioClient>(new FastioClient(se_counter_map_path, up_counter_map_path, n_keywords));
            c_ptr->write_keys(dir_path); // keys are chose randomly from class PRFBase !
            
            return c_ptr;
        }
        
        FastioClient::FastioClient(const std::string& se_map_path, const std::string& up_map_path, const size_t tm_setup_size) :
        k_prf_(), s_prf_(), se_counter_map_(se_map_path), up_counter_map_(up_map_path)
        {
            
        }

        FastioClient::FastioClient(const std::string& se_map_path, const std::string& up_map_path, const std::string& derivation_master_key, const std::string& state_master_key) :
        k_prf_(derivation_master_key), s_prf_(state_master_key), se_counter_map_(se_map_path), up_counter_map_(up_map_path)
        {
            
        }      
        
        FastioClient::~FastioClient()
        {
            
        }
        
        size_t FastioClient::keyword_count() const
        {
            return up_counter_map_.approximate_size();
        }
             
        const std::string FastioClient::master_derivation_key() const
        {
            return std::string(k_prf_.key().begin(), k_prf_.key().end());
        }

        const std::string FastioClient::state_derivation_key() const
        {
            return std::string(s_prf_.key().begin(), s_prf_.key().end());
        }
        
        const crypto::Prf<kDerivationKeySize>& FastioClient::derivation_prf() const
        {
            return k_prf_;
        }

        const crypto::Prf<kStateKeySize>& FastioClient::state_prf() const
        {// used for state evaluation
            return s_prf_;
        }
        
        std::string FastioClient::get_keyword_index(const std::string &kw) const
        {   // 对关键字进行哈希，得到一个索引
            std::string hash_string = crypto::Hash::hash(kw);
            return hash_string.erase(kKeywordIndexSize); // erasing content from kKeywordIndexSize to the end
        }
        
        SearchRequest FastioClient::search_request(const std::string &keyword) 
        {

            uint32_t se_counter;
            uint32_t up_counter;

            bool found;
            SearchRequest req;
            req.add_count = 0;

            std::string seed = get_keyword_index(keyword);
            
            found = se_counter_map_.get(keyword, se_counter);
            found = up_counter_map_.get(keyword, up_counter);

            if(!found)
            {
                logger::log(logger::INFO) << "No matching search/update counter found for keyword " << keyword << " (index " << keyword << ")" << std::endl;
            }else{
                /*
                  generate token(state token), derivation key (keyword identifier) 
                  and up_counter(updating time since last search)
                */
                req.token = state_prf().prf_string(seed + std::to_string(se_counter));
                req.derivation_key = derivation_prf().prf_string(seed);
                req.add_count = up_counter + 1;  //[0, up_counter]

                se_counter++;
                up_counter = -1;/* set as -1 (ATTENTION, up_counter is uint32_t, unsigned type), 
                                   but get_and_increment() will increase up_counter then, so it's fine.
                                */
                bool success = se_counter_map_.set(keyword, se_counter);
                assert(success);

                success = up_counter_map_.set(keyword, up_counter);
                assert(success);
            }
            
            // logger::log(logger::INFO) << "counter: " << up_counter << std::endl;

            return req;
        }
        
        
        // the function is used for generate the newest state for keyword during update
        bool FastioClient::gen_state(const std::string keyword, std::string& state) {
            // only used for update !

            uint32_t se_counter;
            
            std::string seed = get_keyword_index(keyword);

            // get the current search counter, set as 0 if not existing !
            bool success = true;

            bool existed= se_counter_map_.get(keyword, se_counter);
            if( !existed ){
                 success = se_counter_map_.set(keyword, 0);
                 se_counter = 0;
            }
 
            state = state_prf().prf_string(seed + std::to_string(se_counter));

            return success; // success = false if `set` not success
        }
        
        UpdateRequest FastioClient::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest req;
            search_token_type st;
            
            // get (and possibly construct) the keyword index
            std::string seed = get_keyword_index(keyword);

            // retrieve the counter
            uint32_t up_counter;
                        
            // get the increased update counter
            bool success = up_counter_map_.get_and_increment(keyword, up_counter);
            assert(success);            
            
            success = gen_state(keyword, st);
            assert(success);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "State: " << hex_string(st) << std::endl;
            }
            
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            gen_update_token_masks(st, std::to_string(up_counter), req.token, mask);
            req.index = xor_mask(index, mask);

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
        
        std::ostream& FastioClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
            
            return out;
        }
        
        void FastioClient::write_keys(const std::string& dir_path) const
        {
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string state_key_path = dir_path + "/" + state_key_file__;
                      
            std::ofstream master_key_out(master_key_path.c_str()), state_key_out(state_key_path.c_str());
            if (!master_key_out.is_open()) {
                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
            }

            if (!state_key_out.is_open()) {
                throw std::runtime_error(state_key_path + ": unable to write the state derivation key");
            }

            master_key_out << master_derivation_key();
            master_key_out.close();

            state_key_out << state_derivation_key();
            state_key_out.close();
        }
    }
}
