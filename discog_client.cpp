//
//  discog_client.cpp
//  discog
//
//  Created by Raphael Bost on 20/07/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "discog/client_runner.hpp"
#include "utils/logger.hpp"
#include "aux/db_generator.hpp"

#include <sse/crypto/utils.hpp>


#include <list>
#include <mutex>
#include <iostream>

#include <unistd.h>
#include <stdio.h>

__thread std::list<std::pair<std::string, uint64_t>> *buffer_list__ = NULL;

int main(int argc, char** argv) {
    sse::logger::set_severity(sse::logger::INFO);
    sse::logger::set_benchmark_file("benchmark_discog_client.out");
    
    sse::crypto::init_crypto_lib();
    
    opterr = 0;
    int c;

    std::list<std::string> input_files;
    std::list<std::string> keywords;
    std::string client_db;
    bool print_stats = false;
    uint32_t rnd_entries_count = 0;
    uint32_t global_up_count = 0; // for disco
    
    bool print_results = true;
    bool new_batch = false;

    while ((c = getopt (argc, argv, "l:b:dpe:r:q")) != -1)
        switch (c)
    {
        case 'l':
            input_files.push_back(std::string(optarg));
            break;
        case 'b':
            client_db = std::string(optarg);
            break;
        case 'd': // load a default file, only for debugging
//            input_files.push_back("/Volumes/Storage/WP_Inverted/inverted_index_all_sizes/inverted_index_10000.json");
            input_files.push_back("/Users/raphaelbost/Documents/inverted_index_1000.json");
            break;
        case 'p':
            print_stats = true;
            break;
        case 'e':
            // new_batch = true;
            global_up_count = (uint32_t)std::stod(std::string(optarg),nullptr);
            break;
        case 'q':
            print_results = false;
            break;
        case 'r':
            rnd_entries_count = (uint32_t)std::stod(std::string(optarg),nullptr);
            //atol(optarg);
            break;
        case '?':
            if (optopt == 'l' || optopt == 'b' || optopt == 'o' || optopt == 'i' || optopt == 't' || optopt == 'r')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            exit(-1);
    }
    
    
    for (int index = optind; index < argc; index++)
    {
          keywords.push_back(std::string(argv[index]));
    }

    if (client_db.size()==0) {
        sse::logger::log(sse::logger::WARNING) << "Client database not specified" << std::endl;
        sse::logger::log(sse::logger::WARNING) << "Using \'test.dcdb\' by default" << std::endl;
        client_db = "test.dcdb";
    }else{
        sse::logger::log(sse::logger::INFO) << "Running client with database " << client_db << std::endl;
    }
    
    std::unique_ptr<sse::discog::DiscogClientRunner> client_runner;
    
    size_t setup_size = 1e5;
    uint32_t n_keywords = 1e4;
    
    if( rnd_entries_count > 0)
    {
        setup_size = 11*rnd_entries_count;
        n_keywords = 1.4*rnd_entries_count/(10*std::thread::hardware_concurrency());
    }
    
    client_runner.reset( new sse::discog::DiscogClientRunner("localhost:4241", client_db, setup_size, n_keywords) );
    
//    if (new_batch == true) 
//    {
//        client_runner->prepare_new_batch(); 
//    }

    for (std::string &path : input_files) {
        sse::logger::log(sse::logger::INFO) << "Load file " << path << std::endl;
        client_runner->load_inverted_index(path);
        sse::logger::log(sse::logger::INFO) << "Done loading file " << path << std::endl;
    }
    
    if (rnd_entries_count >= 0) {
        sse::logger::log(sse::logger::INFO) << "Randomly generating database with " << rnd_entries_count << " docs" << std::endl;

        std::mutex buffer_mtx;

        std::atomic_uint upt_size(0);
        auto gen_callback = [&client_runner, &upt_size](const std::string &s, size_t i)
        {
            if (buffer_list__ == NULL) {
                buffer_list__ = new std::list<std::pair<std::string, uint64_t>>();
            }
            buffer_list__->push_back(std::make_pair(s, i));
            
            if (buffer_list__->size() >= 50) {
                client_runner->async_update(*buffer_list__);
                
                buffer_list__->clear();
            }
            //client_runner->async_update(s, i);
            upt_size++;
        };
        
        BENCHMARK_Q((
        {   
            client_runner->start_update_session();
            for ( uint32_t i = 0; i < global_up_count; i++){

                client_runner->prepare_new_batch();     
                sse::sophos::disco_gen_db(rnd_entries_count/global_up_count, i * (rnd_entries_count/global_up_count), gen_callback);
            }
            client_runner->end_update_session();
        }), upt_size, PRINT_BENCH_SEARCH_PAR_RPC);

    }
    
    for (std::string &kw : keywords) {
        std::cout << "-------------- Search --------------" << std::endl;
        
        std::mutex logger_mtx;
        std::ostream& log_stream = sse::logger::log(sse::logger::INFO);
        bool first = true;
        
        std::atomic_uint res_size(0);
        auto print_callback = [&logger_mtx, &log_stream, &first, &res_size, print_results](uint64_t res)
        {   /* FIXME: NOT PRINTING
            if (print_results) {
             logger_mtx.lock();

             if (!first) {
                 log_stream << ", ";
             }
             first = false;
             log_stream << res;
            
             logger_mtx.unlock();
            }*/
            res_size++;
        };
        
        // log_stream << "Search results: \n{";

        // auto res = client_runner->search(kw, print_callback);

        BENCHMARK_Q((client_runner->search(kw, print_callback)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
        
        // log_stream << "}" << std::endl;
         log_stream << "result size:" << res_size << std::endl;
    }
    
    
    if (print_stats)
    {
        // client_runner->print_stats(sse::logger::log(sse::logger::INFO));
    }
    
    client_runner.reset();
    
    sse::crypto::cleanup_crypto_lib();

    
    return 0;
}
