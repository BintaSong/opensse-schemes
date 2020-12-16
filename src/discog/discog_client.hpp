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
#include "types.hpp"

#include "discog_common.hpp"

#include "utils/rocksdb_wrapper.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"

#include <sse/crypto/block_hash.hpp>

#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/prettywriter.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>

#include <sse/crypto/prf.hpp>

namespace sse {
    namespace discog {
        
        template <typename T>
        class DiscogClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;
            typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;
            typedef T index_type;

            static constexpr size_t kTreeDepth = 48;
            
            DiscogClient(const std::string& counter_path);
            DiscogClient(const std::string& counter_path, const std::string& derivation_master_key, const std::string& kw_token_master_key, const uint32_t global_counter);
            ~DiscogClient();

            size_t keyword_count() const;
            
            const std::string master_derivation_key() const;
            const std::string kw_token_master_key() const;
            
            keyword_index_type get_keyword_index(const std::string &kw) const;

            //uint32_t get_match_count(const std::string &kw) const;

            SearchRequest       search_request(const std::string &keyword, bool log_not_found = true) const;
            UpdateRequest<T>    update_request(const std::string &keyword, const index_type index);
            std::list<UpdateRequest<T>>   bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list);

            bool remove_keyword(const std::string &kw);

//            SearchRequest   search_request_index(const keyword_index_type &kw_index) const;
//            SearchRequest   random_search_request() const;

            // std::ostream& print_stats(std::ostream& out) const;
            
            const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
            const crypto::Prf<kKeywordTokenSize>& kw_token_prf() const;
            
            static const std::string derivation_keys_file__;

            const uint32_t get_global_counter() const;
            const void increase_global_counter() const;            

        private:

            // std::list<std::tuple<std::string, T, uint32_t>>   get_counters_and_increment(const std::list<std::pair<std::string, index_type>> &update_list);

            crypto::Prf<kSearchTokenKeySize> root_prf_;
            crypto::Prf<kKeywordTokenSize> kw_token_prf_;
            
            
            //sophos::RocksDBCounter counter_map_;
            std::atomic_uint keyword_counter_;

            
            std::string global_counter_file__;
            // std::string main_directory_path;
            uint32_t shared_global_counter;

            std::map<std::string, uint32_t> local_counter_map; // record level-2 local counter during batch update
            std::mutex local_counter_map_mtx_;
            
            uint32_t get_and_increase_local_counter(const std::string &keyword, uint32_t &keyword_local_counter); 
        };
        
        

    }
}


namespace sse {
    namespace discog {
        
        //template <typename T> const std::string DiscogClient<T>::global_counter_file__ = "global_counter.dat"; 

        template <typename T>
        DiscogClient<T>::DiscogClient(const std::string& counter_path) :
        root_prf_(), kw_token_prf_(), global_counter_file__(counter_path), shared_global_counter(-1)
        {
            
        }
        
        template <typename T>
        DiscogClient<T>::DiscogClient(const std::string& counter_path, const std::string& derivation_master_key, const std::string& kw_token_master_key, const uint32_t global_counter) :
        root_prf_(derivation_master_key), kw_token_prf_(kw_token_master_key), global_counter_file__(counter_path), shared_global_counter(global_counter)
        {
            
        }
        
        template <typename T>
        DiscogClient<T>::~DiscogClient()
        {
            // const std::string SophosClient::global_counter_file__;
            // std::string counter_path = main_directory_path + "/" + global_counter_file__;
            std::ofstream counter_out(global_counter_file__.c_str());
            if (!counter_out.is_open()) {
                throw std::runtime_error(global_counter_file__ + ": unable to write the global counter file.");
            }
            
            counter_out << shared_global_counter; // store global counter into file
            counter_out.close();
        }
        
        template <typename T>
        const std::string DiscogClient<T>::master_derivation_key() const
        {
            return std::string(root_prf_.key().begin(), root_prf_.key().end());
        }
        
        template <typename T>
        const std::string DiscogClient<T>::kw_token_master_key() const
        {
            return std::string(kw_token_prf_.key().begin(), kw_token_prf_.key().end());
        }
        
        
        template <typename T>
        typename DiscogClient<T>::keyword_index_type DiscogClient<T>::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            
            keyword_index_type ret;
            std::copy_n(hash_string.begin(), kKeywordIndexSize, ret.begin());
            
            return ret;
        }

        /*
        template <typename T>
        uint32_t DiscogClient<T>::get_match_count(const std::string &kw) const
        {
            uint32_t kw_counter;

            bool found = counter_map_.get(kw, kw_counter); 
            
            return (found) ? kw_counter : 0;
        }
        */
        template <typename T> 
        const uint32_t DiscogClient<T>::get_global_counter() const 
        {
            return shared_global_counter;
        }

        template <typename T> 
        const void DiscogClient<T>::increase_global_counter() const // MUST call this function before batch update!
        {
            int *point = (int*) &shared_global_counter;
            *point = shared_global_counter + 1; 
            // shared_global_counter = shared_global_counter + 1; // FIXME: wrong usecase
        }
        
        // maintain local counter for level-2 index during update, no need to store in file after execution.
        template <typename T>
        uint32_t DiscogClient<T>::get_and_increase_local_counter(const std::string &keyword, uint32_t &keyword_local_counter)
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

        template <typename T>
        SearchRequest   DiscogClient<T>::search_request(const std::string &keyword, bool log_not_found) const
        {
            keyword_index_type kw_index = get_keyword_index(keyword);
            
            // bool found;
            uint32_t global_counter;
            SearchRequest req;
            req.add_count = 0;
            
            // found = counter_map_.get(keyword, kw_counter); // FIXME: 
            global_counter = get_global_counter();

            /*if(!found)
            {
                if (log_not_found) {
                    logger::log(logger::INFO) << "No matching counter found for keyword " << hex_string(std::string(kw_index.begin(),kw_index.end())) << std::endl;
                }
            }else{*/
                req.add_count = global_counter+1;
                
                // Compute the root of the tree attached to kw_index
                
                TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
                
                req.token_list = TokenTree::covering_list(root, req.add_count, kTreeDepth);
        
                // set the kw_token
                req.kw_token = kw_token_prf_.prf(kw_index);

            //}
            
            return req;

        }
        
        template <typename T>
        UpdateRequest<T>   DiscogClient<T>::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest<T> req;
            search_token_key_type st;
            index_type mask;
            
            // get (and possibly construct) the keyword index
            keyword_index_type kw_index = get_keyword_index(keyword);
            std::string seed(kw_index.begin(),kw_index.end());
            
            // retrieve the counter
            uint32_t global_counter, local_counter;
            
            //bool success = counter_map_.get_and_increment(keyword, kw_counter);
            global_counter = get_global_counter();
            get_and_increase_local_counter(keyword, local_counter);

            // assert(success);
            
            TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
            
            st = TokenTree::derive_node(root, global_counter, kTreeDepth);
            
            //if (logger::severity() <= logger::DBG) {
            //logger::log(logger::DBG) << "[CLIENT] New ST: " << hex_string(st) << " for global counter: "<< global_counter << std::endl;
            //}
            
            // we use st to derive a new local_st for level-2 index
            // FIXME: **MUST** PAY ATTENTION TO THE PRF KEY SIZE !
            crypto::Prf<TokenTree::kTokenSize> local_prf(st.data(), st.size()); //kSearchTokenKeySize = 16
            logger::log(logger::DBG) << "[CLIENT] local_prf key data: " << hex_string(std::string((const char*)local_prf.key_data(), TokenTree::kTokenSize)) << std::endl;

            search_token_key_type local_st = local_prf.prf(std::to_string(local_counter)); // kSearchTokenKeySize == crypto::Prg::kKeySize
            // logger::log(logger::DBG) << "[CLIENT] INPUT: " << hex_string(std::string((const char*)st.data(), TokenTree::kTokenSize)) << std::endl;
            logger::log(logger::DBG) << "[CLIENT] local token: " << hex_string(local_st) << " for local counter: "<< std::to_string(local_counter) << std::endl;
            

            //crypto::Prf<TokenTree::kTokenSize> local_prf2 = crypto::Prf<TokenTree::kTokenSize>(st.data(), st.size()); //kSearchTokenKeySize = 16
            //logger::log(logger::DBG) << "[CLIENT] local_prf2 key data: " << hex_string(std::string((const char*)local_prf2.key_data(), TokenTree::kTokenSize)) << std::endl;
            //search_token_key_type local_st2 = local_prf2.prf(std::string((const char*)st.data(), TokenTree::kTokenSize)); // kSearchTokenKeySize == crypto::Prg::kKeySize
            //logger::log(logger::DBG) << "[CLIENT] INPUT: " << hex_string(std::string((const char*)st.data(), TokenTree::kTokenSize)) << std::endl;
            //logger::log(logger::DBG) << "[CLIENT] local token: " << hex_string(local_st) << " for local counter: "<< std::to_string(local_counter) << std::endl;

            gen_update_token_mask(local_st, req.token, mask);

            req.index = xor_mask(index, mask);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "[CLIENT] Update Request: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
 
        template <typename T>
        std::list<UpdateRequest<T>>   DiscogClient<T>::bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list)
        {
            std::string keyword;
            index_type index;
            
            std::list<UpdateRequest<T>> req_list;
            
            // std::list<std::tuple<std::string, T, uint32_t>> counter_list = get_counters_and_increment(update_list);
            
            // use the shared global counter for batch update
            uint32_t global_counter = get_global_counter();

            for (auto it = update_list.begin(); it != update_list.end(); ++it) {
                
                keyword = std::get<0>(*it);
                index = std::get<1>(*it);
                UpdateRequest<T> req;
                search_token_key_type st;
                index_type mask;
                
                // get (and possibly construct) the keyword index
                keyword_index_type kw_index = get_keyword_index(keyword);
                std::string seed(kw_index.begin(),kw_index.end());
              
                TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
                
                st = TokenTree::derive_node(root, global_counter, kTreeDepth);
        
                // retrieve the local counter
                uint32_t local_counter;
                get_and_increase_local_counter(keyword, local_counter);
                
                // we use `st` to derive a new `local_st` for level-2 index update
                // FIXME: **MUST** PAY ATTENTION TO THE PRF KEY SIZE ! (crypto::Prf<TokenTree::kTokenSize>(const void* k) will read more data than st.size()!)
                auto local_prf = crypto::Prf<TokenTree::kTokenSize>(st.data(), st.size()); // TokenTree::kTokenSize == 16
                search_token_key_type local_st = local_prf.prf(std::to_string(local_counter)); // kSearchTokenKeySize == crypto::Prg::kKeySize
                
                gen_update_token_mask(local_st, req.token, mask);
                
                logger::log(logger::DBG) << "[CLIENT] local token: " << hex_string(local_st) << " for local counter: "<< local_counter << std::endl;

                req.index = xor_mask(index, mask);
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "[CLIENT] Update Request: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
                }
                req_list.push_back(req);
            }
            
            return req_list;
        }
        
        /*        
        template <typename T>
        std::list<std::tuple<std::string, T, uint32_t>>   DiscogClient<T>::get_counters_and_increment(const std::list<std::pair<std::string, index_type>> &update_list)
        {
            std::string keyword;
            index_type index;
            
            std::list<std::tuple<std::string, index_type, uint32_t>> res;
            
            
            for (auto it = update_list.begin(); it != update_list.end(); ++it) {
                
                
                
                keyword = it->first;
                index = it->second;
 
                // retrieve the counter
                uint32_t kw_counter;
                bool success = counter_map_.get_and_increment(keyword, kw_counter);
                
                assert(success);
                
                res.push_back(std::make_tuple(keyword, index, kw_counter));

            }
            
            return res;
        }
        */

        template <typename T>
        bool DiscogClient<T>::remove_keyword(const std::string &kw)
        {   //TODO: 
            //return counter_map_.remove_key(kw);
        } 
        
        /*template <typename T>
        std::ostream& DiscogClient<T>::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
           
            return out;
        }
        
        
        template <typename T>
        size_t DiscogClient<T>::keyword_count() const
        {
            return counter_map_.approximate_size();
        }
        */

    }
}
