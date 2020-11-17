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

#include "fastio_server.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
namespace fastio {
    

FastioServer::FastioServer(const std::string& db_path, const std::string& cache_path) :
edb_(db_path), cache_(cache_path)
{
    
}

FastioServer::FastioServer(const std::string& db_path, const std::string& cache_path, const size_t tm_setup_size) :
    edb_(db_path), cache_(cache_path)
{
    
}


std::list<index_type> FastioServer::search(const SearchRequest& req)
{
    std::list<index_type> results;
    
    search_token_type st = req.token;

    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Counter: " << req.add_count << std::endl;

        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    for (size_t i = 0; i < req.add_count; i++) {

        index_type r;
        update_token_type ut;

        std::array<uint8_t, kUpdateTokenSize> mask;

        gen_update_token_masks(st, std::to_string(i), ut, mask);
        
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
        }

        bool found = edb_.get(ut, r);
        
        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found, before de-mask: " << hex_string(r) << std::endl;
            }
            
            r = xor_mask(r, mask);
            results.push_back(hex_string(r));

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found, after de-mask: " << hex_string(r) << std::endl;
            }
        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }
    }

    // get cached indexes
    std::string cache_indexes;
    if(req.derivation_key.compare("") != 0) cache_.get(req.derivation_key, cache_indexes);

    auto split_and_restore = [&cache_indexes, &results, this] ( const std::string key) {

        size_t len = cache_indexes.size();
        std::string new_cache_indexes = accumulate(begin(results), end(results), cache_indexes); // O(c')

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Previous Cacheed indexes length: " << len << std::endl;
        }

        for(size_t t = 0; t < len; t += 2*kUpdateTokenSize) {
            std::string index = cache_indexes.substr(t, 2*kUpdateTokenSize);
            results.push_back( index );
        }

        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Current indexes length: " << new_cache_indexes.size() << std::endl;
        }

        bool success = cache_.remove_and_put(key, new_cache_indexes);
        assert(success);
    };
    
    // split cacheed_indexed into results
    // *ATTENTION*: must check req.derivation_key != ""
    if(req.derivation_key.compare("") != 0) {
        split_and_restore( req.derivation_key );
    }

    return results;
}

    void FastioServer::search_callback(const SearchRequest& req, std::function<void(index_type)> post_callback)
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

            // logger::log(logger::INFO) << "ST: " << hex_string(st) << std::endl;

            gen_update_token_masks(st, std::to_string(i), ut, mask);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
            }
            
            bool found = edb_.get(ut,r);
            
            if (found) {
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Found, before de-mask: " << hex_string(r) << std::endl;
                }
                
                // unmask r
                r = xor_mask(r, mask);
                results.push_back(hex_string(r));

                post_callback( hex_string(r) );

                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Found, after de-mask: " << hex_string(r) << std::endl;
                }

            }else{
                logger::log(logger::ERROR) << "i = "<< i << ", We were supposed to find something!" << std::endl;
            }
        }// end for 


        // get cached indexes
        std::string cache_indexes;
        if(req.derivation_key.compare("") != 0) cache_.get(req.derivation_key, cache_indexes);

        auto split_and_restore = [&cache_indexes, &results, &post_callback, this] ( const std::string key) {
            // merge new index into cache index
            std::string new_cache_indexes = accumulate(begin(results), end(results), cache_indexes); // O(c')


            size_t len = cache_indexes.size();

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Previous cacheed indexes length: " << len << std::endl;
            }

            // parse cache index, add into results
            for(size_t t = 0; t < len; t += 2*kUpdateTokenSize) {
                std::string index = cache_indexes.substr(t, 2*kUpdateTokenSize);
                
                results.push_back( (index) );
                post_callback( index );
            }

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Current indexes length: " <<  new_cache_indexes.size() << std::endl;               
            }

            bool success = cache_.remove_and_put(key, new_cache_indexes);
            assert(success);
        };
        
        // split and re-cache
        if(req.derivation_key.compare("") != 0) split_and_restore( req.derivation_key );

    }
    
    std::list<index_type> FastioServer::search_parallel(const SearchRequest& req)
    {
        std::list<index_type> results;
        std::mutex res_mutex;
        std::mutex cache_mutex;

        search_token_type st = req.token;
        
        auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.token);


        std::string cache_indexes;
    
        auto get_cache_job = [&cache_indexes, &results, &res_mutex, &cache_mutex, this] ( const std::string key ) {
            
            std::string pre_cached_indexes;

            bool found = cache_.get(key, pre_cached_indexes);
            if (found) {
                // take care of multi-threads effects
                cache_mutex.lock();
                cache_indexes += pre_cached_indexes;
                cache_mutex.unlock();

                size_t len = cache_indexes.size();
        
                for(size_t t = 0; t < len; t += 2*kUpdateTokenSize) {
                    std::string index = pre_cached_indexes.substr(t, 2*kUpdateTokenSize);

                    res_mutex.lock();
                    results.push_back(hex_string(index)); 
                    res_mutex.unlock();
                }
            }
        };

    
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
        
            logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
        }

        ThreadPool partition_pool(std::thread::hardware_concurrency() - 1);
    
        auto partition_job = [&derivation_prf, &results, &cache_indexes, &res_mutex, &cache_mutex, &st, this](const uint8_t index, const size_t max, const uint8_t step)
        {
            search_token_type local_st = st;

            index_type r;
            update_token_type ut;
    
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            for (size_t i = index; i < max; i += step) {

                gen_update_token_masks(st, std::to_string(i), ut, mask);

                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
                }
                
                bool found = edb_.get(ut,r);
                
                if (found) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Found: " << hex_string(r) << std::endl;
                    }
                    
                    // unmask r
                    r = xor_mask(r, mask);

                    res_mutex.lock();
                    results.push_back(r);
                    res_mutex.unlock();

                    // TODO ==> might creating a cache_job here be better? need to test!
                    cache_mutex.lock();
                    cache_indexes += hex_string(r);  // append cache_indexes on the fly
                    cache_mutex.unlock();
                
                }else {
                    logger::log(logger::ERROR) << "i = "<< i << ", We were supposed to find something!" << std::endl;
                }
            }
        };


        std::vector<std::thread> search_threads;

        search_threads.push_back(std::thread(get_cache_job, req.derivation_key));
        

        unsigned n_threads = std::thread::hardware_concurrency() - 1;
        
        for (uint8_t t = 0; t < n_threads; t++) {
            search_threads.push_back(std::thread(partition_job, t, req.add_count, n_threads));
        }
     
        for (auto& t : search_threads) {
            t.join();
        }

        if(req.derivation_key.compare("") != 0) {
            bool success = cache_.remove_and_put(req.derivation_key, cache_indexes);
            assert(success);
        }
        return results;
    }  



    std::list<index_type> FastioServer::search_parallel_callback(const SearchRequest& req, std::function<void(index_type)> post_callback)
    {
        std::list<index_type> results;
        std::mutex res_mutex;
        std::mutex cache_mutex;

        search_token_type st = req.token;
        
        auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.token);


        std::string cache_indexes;
    
        auto get_cache_job = [&cache_indexes, &results, &res_mutex, &cache_mutex, &post_callback, this] ( const std::string key ) {
            
            std::string pre_cached_indexes;
            bool found = cache_.get(key, pre_cached_indexes);
            
            if (found) {
                // take care of multi-threads effects
                cache_mutex.lock();
                cache_indexes += pre_cached_indexes;
                cache_mutex.unlock();

                size_t len = pre_cached_indexes.size();
        
                for(size_t t = 0; t < len; t += 2*kUpdateTokenSize) {
                    std::string index = pre_cached_indexes.substr(t, 2*kUpdateTokenSize);

                    res_mutex.lock();
                    results.push_back(hex_string(index));
                    res_mutex.unlock();

                    post_callback(index);
                }
            }
        };

    
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
        
            logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
        }

        ThreadPool partition_pool(std::thread::hardware_concurrency() - 1);
    
        auto partition_job = [&derivation_prf, &results, &cache_indexes, &st, &res_mutex, &cache_mutex, &post_callback, this](const uint8_t index, const size_t max, const uint8_t step)
        {
            search_token_type local_st = st;

            index_type r;
            update_token_type ut;
    
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            for (size_t i = index; i < max; i += step) {

                gen_update_token_masks(st, std::to_string(i), ut, mask);

                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
                }
                
                bool found = edb_.get(ut,r);
                
                if (found) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Found: " << hex_string(r) << std::endl;
                    }
                    
                    // unmask r
                    r = xor_mask(r, mask);


                    res_mutex.lock();
                    results.push_back(hex_string(r));
                    res_mutex.unlock();

                    cache_mutex.lock();
                    cache_indexes += hex_string(r);   // append cache_indexes on the fly
                    cache_mutex.unlock();

                    post_callback(hex_string(r));

                }else {
                    logger::log(logger::ERROR) << "i = "<< i << ", We were supposed to find something!" << std::endl;
                }
            }
        };


        std::vector<std::thread> search_threads;

        search_threads.push_back(std::thread(get_cache_job, req.derivation_key));
        

        unsigned n_threads = std::thread::hardware_concurrency() - 1;
        
        for (uint8_t t = 0; t < n_threads; t++) {
            search_threads.push_back(std::thread(partition_job, t, req.add_count, n_threads));
        }
     
        for (auto& t : search_threads) {
            t.join();
        }
        if(req.derivation_key.compare("") != 0){
            bool success = cache_.remove_and_put(req.derivation_key, cache_indexes);
            assert(success);
        }

        return results;
    }  


std::list<index_type> FastioServer::search_parallel_full(const SearchRequest& req)
{
    std::list<index_type> results;
    
    std::mutex res_mutex;
    std::mutex cache_mutex;
    
    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.token);
    
    std::string cache_indexes;
    
    auto get_cache_job = [&cache_indexes, &results, &res_mutex, &cache_mutex, this] ( const std::string key ) {
        
        std::string pre_cached_indexes;
        bool found = cache_.get(key, pre_cached_indexes);

        if(found){
            cache_mutex.lock();
            cache_indexes += pre_cached_indexes;
            cache_mutex.unlock();

            size_t len = pre_cached_indexes.size();
        
            for(size_t t = 0; t < len; t += 2*kUpdateTokenSize) {
                std::string index = pre_cached_indexes.substr(t, 2*kUpdateTokenSize);

                res_mutex.lock();
                results.push_back( hex_string(index) );
                res_mutex.unlock();
            }
        }
    };
    
    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    ThreadPool partition_pool(1);
    ThreadPool lookup_pool(2);
    ThreadPool decrypt_pool(1);

    auto decrypt_job = [&derivation_prf, &results, &cache_indexes, &res_mutex, &cache_mutex](const index_type r, const std::string& st_string)
    {
        index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
        
        res_mutex.lock();
        results.push_back(hex_string(v));
        res_mutex.unlock();

        cache_mutex.lock();
        cache_indexes += hex_string(v);   // append cache_indexes on the fly
        cache_mutex.unlock();

    };

    auto lookup_job = [&derivation_prf, &decrypt_pool, &decrypt_job, this](const std::string& st_string, const update_token_type& token)
    {
        index_type r;
        
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
        }
        
        bool found = edb_.get(token, r);
        
        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << hex_string(r) << std::endl;
            }
            
        decrypt_pool.enqueue(decrypt_job, r, st_string);

        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }

    };

    auto partition_job = [&derivation_prf, &lookup_pool, &lookup_job, &st](const uint8_t index, const size_t max, const uint8_t step)
    {
        search_token_type local_st = st;
        
        for (size_t i = index; i < max; i += step) {
            update_token_type ut = derivation_prf.prf_string(std::to_string(i) + '0').erase(kUpdateTokenSize);
            lookup_pool.enqueue(lookup_job, st, ut);
        }
    };


    std::vector<std::thread> search_threads;
    
    unsigned n_threads = std::thread::hardware_concurrency()-3;
    
    for (uint8_t t = 0; t < n_threads; t++) {
        search_threads.push_back(std::thread(partition_job, t, req.add_count, n_threads));
    }
 
    for (uint8_t t = 0; t < n_threads; t++) {
        search_threads[t].join();
    }

    decrypt_pool.join();
    lookup_pool.join();
    
    if(req.derivation_key.compare("") != 0) {
        bool success = cache_.remove_and_put(req.derivation_key, cache_indexes);
        assert(success);
    }

    return results;
}


std::list<index_type> FastioServer::search_parallel_full_callback(const SearchRequest& req, std::function<void(index_type)> post_callback)
{
    std::list<index_type> results;
    std::mutex res_mutex;
    std::mutex cache_mutex;
    
    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.token);
    
    std::string cache_indexes;
    
    auto get_cache_job = [&cache_indexes, &results, &res_mutex, &cache_mutex, &post_callback, this] ( const std::string key ) {
        
        std::string pre_cached_indexes;
        bool found = cache_.get_append(key, pre_cached_indexes);
        
        if (found) {
            // take care of multi-threads effects
            cache_mutex.lock();
            cache_indexes += pre_cached_indexes;
            cache_mutex.unlock();

            size_t len = pre_cached_indexes.size();
        
            for(size_t t = 0; t < len; t += 2*kUpdateTokenSize) {
                std::string index = pre_cached_indexes.substr(t, 2*kUpdateTokenSize);

                res_mutex.lock();
                results.push_back( hex_string(index) );
                res_mutex.unlock();

                post_callback(index);        
                
            }
        }
    };
    
    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }

    ThreadPool partition_pool(1);
    ThreadPool lookup_pool(2);
    ThreadPool decrypt_pool(1);

    auto decrypt_job = [&derivation_prf, &results, &cache_indexes, &post_callback, &res_mutex, &cache_mutex](const index_type r, const std::string& st_string)
    {
        index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
        
        res_mutex.lock();
        results.push_back(hex_string(v));
        res_mutex.unlock();

        cache_mutex.lock();
        cache_indexes += hex_string(v);   // append cache_indexes on the fly
        cache_mutex.unlock();

        post_callback(hex_string(v));    
        
    };

    auto lookup_job = [&derivation_prf, &decrypt_pool, &decrypt_job, this](const std::string& st_string, const update_token_type& token)
    {
        index_type r;
        
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
        }
        
        bool found = edb_.get(token, r);
        
        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << hex_string(r) << std::endl;
            }
            
        decrypt_pool.enqueue(decrypt_job, r, st_string);

        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }

    };

    auto partition_job = [&derivation_prf, &lookup_pool, &lookup_job, &st](const uint8_t index, const size_t max, const uint8_t step)
    {
        search_token_type local_st = st;
        
        for (size_t i = index; i < max; i += step) {
            update_token_type ut = derivation_prf.prf_string(std::to_string(i) + '0').erase(kUpdateTokenSize);
            lookup_pool.enqueue(lookup_job, st, ut);
        }
    };


    std::vector<std::thread> search_threads;
    
    unsigned n_threads = std::thread::hardware_concurrency()-3;
    
    for (uint8_t t = 0; t < n_threads; t++) {
        search_threads.push_back(std::thread(partition_job, t, req.add_count, n_threads));
    }
 
    for (uint8_t t = 0; t < n_threads; t++) {
        search_threads[t].join();
    }

    decrypt_pool.join();
    lookup_pool.join();
    
    if(req.derivation_key.compare("") != 0) {
        bool success = cache_.remove_and_put(req.derivation_key, cache_indexes);
        assert(success);
    }

    return results;
}

void FastioServer::update(const UpdateRequest& req)
{
    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Update: (" << hex_string(req.token) << ", " << hex_string(req.index) << ")" << std::endl;
    }

//    edb_.add(req.token, req.index);
    edb_.put(req.token, req.index);
}

std::ostream& FastioServer::print_stats(std::ostream& out) const
{
//    out << "Number of tokens: " << edb_.size();
//    out << "; Load: " << edb_.load();
//    out << "; Overflow bucket size: " << edb_.overflow_size() << std::endl;
    
    return out;
}

} // namespace fastio
} // namespace sse
