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

#include "server_runner.hpp"

#include "utils/utils.hpp"
#include "utils/logger.hpp"

#include <fstream>
#include <atomic>
#include <thread>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>


namespace sse {
    namespace discog {
        
        const std::string DiscogImpl::pairs_map_file = "pairs.dat";
        
        DiscogImpl::DiscogImpl(const std::string& path) :
        storage_path_(path), async_search_(true)
        {
            if (is_directory(storage_path_)) {
                // try to initialize everything from this directory
                
                std::string pairs_map_path  = storage_path_ + "/" + pairs_map_file;
                
                if (!is_directory(pairs_map_path)) {
                    // error, the token map data is not there
                    throw std::runtime_error("Missing data");
                }
                
                
                server_.reset(new DiscogServer<index_type>(pairs_map_path));
            }else if (exists(storage_path_)){
                // there should be nothing else than a directory at path, but we found something  ...
                throw std::runtime_error(storage_path_ + ": not a directory");
            }else{
                // postpone creation upon the reception of the setup message
            }
        }
        
        DiscogImpl::~DiscogImpl()
        {
            flush_server_storage();
        }

        grpc::Status DiscogImpl::setup(grpc::ServerContext* context,
                                       const SetupMessage* message,
                                       google::protobuf::Empty* e)
        {
            
            logger::log(logger::TRACE) << "Setup!" << std::endl;
            
            if (server_) {
                // problem, the server is already set up
                logger::log(logger::ERROR) << "Info: server received a setup message but is already set up" << std::endl;
                
                return grpc::Status(grpc::FAILED_PRECONDITION, "The server was already set up");
            }
            
            // create the content directory but first check that nothing is already there
            
            if (exists(storage_path_))
            {
                logger::log(logger::ERROR) << "Error: Unable to create the server's content directory" << std::endl;
                
                return grpc::Status(grpc::ALREADY_EXISTS, "Unable to create the server's content directory");
            }
            
            if (!create_directory(storage_path_, (mode_t)0700)) {
                logger::log(logger::ERROR) << "Error: Unable to create the server's content directory" << std::endl;
                
                return grpc::Status(grpc::PERMISSION_DENIED, "Unable to create the server's content directory");
            }
            
            // now, we have the directory, and we should be able to conclude the setup
            // however, the bucket_map constructor in SophosServer's constructor can raise an exception, so we need to take care of it
            
            std::string pairs_map_path  = storage_path_ + "/" + pairs_map_file;
            
            try {
                logger::log(logger::INFO) << "Seting up with size " << message->setup_size() << std::endl;
                server_.reset(new DiscogServer<index_type>(pairs_map_path, message->setup_size()));
            } catch (std::exception &e) {
                logger::log(logger::ERROR) << "Error when setting up the server's core" << std::endl;
                
                server_.reset();
                return grpc::Status(grpc::FAILED_PRECONDITION, "Unable to create the server's core.");
            }
            
            logger::log(logger::TRACE) << "Successful setup" << std::endl;
            
            return grpc::Status::OK;
        }

        
        
        
        grpc::Status DiscogImpl::search(grpc::ServerContext* context,
                                        const SearchRequestMessage* mes,
                                        grpc::ServerWriter<SearchReply>* writer)
        {
            if(async_search_){
                return async_search(context, mes, writer);
            }else{
                return sync_search(context, mes, writer);
            }
        }
        
        grpc::Status DiscogImpl::sync_search(grpc::ServerContext* context,
                                             const SearchRequestMessage* mes,
                                             grpc::ServerWriter<SearchReply>* writer)
        {
            if (!server_) {
                // problem, the server is already set up
                return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
            }
            
            logger::log(logger::TRACE) << "Searching ..." << std::endl;
//            std::list<uint64_t> res_list;
            
            SearchRequest req = message_to_request(mes);

            std::vector<uint64_t> res_list(req.add_count);
            
            logger::log(logger::TRACE) << req.add_count << " expected matches" << std::endl;
            

            std::atomic_uint res_size(0);
            
            std::mutex writer_lock;
            
            auto post_callback = [&writer, &res_size, &writer_lock](index_type i)
            {
                SearchReply reply;
                reply.set_result((uint64_t) i);
                
                writer_lock.lock();
                writer->Write(reply);
                writer_lock.unlock();
                
                res_size++;
            };


            if (req.add_count == 0) {
                logger::log(logger::INFO) << "Empty request (no expected match)"  << std::endl;
            }else{
                    BENCHMARK_Q((server_->search(message_to_request(mes), post_callback)), res_size, PRINT_BENCH_SEARCH_PAR_RPC)
                    //BENCHMARK_Q((res_list = server_->search(message_to_request(mes))),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
    //                BENCHMARK_Q((res_list = server_->search_parallel(message_to_request(mes),4,4)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
    //            BENCHMARK_Q((res_list = server_->search_simple_parallel(message_to_request(mes),8)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
                
                
                
                //BENCHMARK_Q((server_->search_simple_parallel(req ,8, res_list)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
                
                
    //            BENCHMARK_Q((res_list = server_->search_parallel(message_to_request(mes),2)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
                //    BENCHMARK_Q((res_list = server_->search_parallel_light(message_to_request(mes),3)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
                //    BENCHMARK_SIMPLE("\n\n",{;})
            /*    
                for (auto& i : res_list) {
                    SearchReply reply;
                    reply.set_result((uint64_t) i);
                    
                    writer->Write(reply);
                }
                */
            }
            logger::log(logger::TRACE) << "Done searching" << std::endl;
            
            
            return grpc::Status::OK;
        }
        
        
        grpc::Status DiscogImpl::async_search(grpc::ServerContext* context,
                                              const SearchRequestMessage* mes,
                                              grpc::ServerWriter<SearchReply>* writer)
        {
            if (!server_) {
                // problem, the server is already set up
                return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
            }
            
            logger::log(logger::TRACE) << "Searching ...";
            
            std::atomic_uint res_size(0);
            
            std::mutex writer_lock;
            
            auto post_callback = [&writer, &res_size, &writer_lock](index_type i)
            {
                SearchReply reply;
                reply.set_result((uint64_t) i);
                
                writer_lock.lock();
                writer->Write(reply);
                writer_lock.unlock();
                
                res_size++;
            };
            
            //if (mes->add_count() >= 40) { // run the search algorithm in parallel only if there are more than 2 results
                
//                BENCHMARK_Q((server_->search_parallel(message_to_request(mes), post_callback, 8, 8)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
                //BENCHMARK_Q((server_->search_simple_parallel(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)

//                BENCHMARK_Q((res_list = server_->search_simple_parallel(message_to_request(mes),8)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
                
//                BENCHMARK_Q((server_->search_simple_parallel(message_to_request(mes), post_callback, std::thread::hardware_concurrency())), PRINT_BENCH_SEARCH_PAR_RPC)

                
//                BENCHMARK_Q((server_->search_parallel_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency(), 8,1)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//                //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//                //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, 10)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
            //}else if (mes->add_count() >= 2) {
//                BENCHMARK_Q((server_->search_parallel(message_to_request(mes), post_callback, 8, 8)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)

                //BENCHMARK_Q((server_->search_simple_parallel(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)

//                BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
            //}else{
                BENCHMARK_Q((server_->search(message_to_request(mes), post_callback)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
            //}
        
            
            logger::log(logger::TRACE) << " done" << std::endl;
            
            
            return grpc::Status::OK;
        }
        
        
        grpc::Status DiscogImpl::update(grpc::ServerContext* context,
                                        const UpdateRequestMessage* mes,
                                        google::protobuf::Empty* e)
        {
            std::unique_lock<std::mutex> lock(update_mtx_);
            
            if (!server_) {
                // problem, the server is already set up
                return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
            }
            
            logger::log(logger::TRACE) << "Updating ..." << std::endl;
            
            server_->update(message_to_request(mes));
            
            logger::log(logger::TRACE) << " done" << std::endl;
            
            return grpc::Status::OK;
        }
        
        grpc::Status DiscogImpl::bulk_update(grpc::ServerContext* context,
                                             grpc::ServerReader<UpdateRequestMessage>* reader, google::protobuf::Empty* e)
        {
            if (!server_) {
                // problem, the server is already set up
                return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
            }
            
            logger::log(logger::TRACE) << "Updating (bulk)..." << std::endl;
            
            UpdateRequestMessage mes;

            uint32_t counter = 0;
            while (reader->Read(&mes)) {
                server_->update(message_to_request(&mes));
                counter++;
            }
            
            logger::log(logger::TRACE) << "Updating (bulk)... done, total updates: "<< counter << std::endl;
                        
            flush_server_storage();
            
            return grpc::Status::OK;
        }
        
        /*
        std::ostream& DiscogImpl::print_stats(std::ostream& out) const
        {
            if (server_) {
                return server_->print_stats(out);
            }
            return out;
        }*/
        
        bool DiscogImpl::search_asynchronously() const
        {
            return async_search_;
        }
        
        void DiscogImpl::set_search_asynchronously(bool flag)
        {
            async_search_ = flag;
        }
        
        
        void DiscogImpl::flush_server_storage()
        {
            if (server_) {
                logger::log(logger::TRACE) << "Flush server storage..." << std::endl;
                
                server_->flush_edb();
                
                logger::log(logger::TRACE) << "Flush server storage... done" << std::endl;

            }
        }
        
        SearchRequest message_to_request(const SearchRequestMessage* mes)
        {
            SearchRequest req;
            
            req.add_count = mes->add_count();
            
            
            for (auto it = mes->token_list().begin(); it != mes->token_list().end(); ++it) {
                
                search_token_key_type st;
                std::copy(it->token().begin(), it->token().end(), st.begin());

                req.token_list.push_back(std::make_pair(st, it->depth()));
            }
            
            std::copy(mes->kw_token().begin(), mes->kw_token().end(), req.kw_token.begin());
            
            return req;
        }
        
        UpdateRequest<DiscogImpl::index_type> message_to_request(const UpdateRequestMessage* mes)
        {
            UpdateRequest<DiscogImpl::index_type> req;
            
            req.index = mes->index();
            std::copy(mes->update_token().begin(), mes->update_token().end(), req.token.begin());
            
            return req;
        }
        
        void run_discog_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr, bool async_search) {
            std::string server_address(address);
            DiscogImpl service(server_db_path);
            
            grpc::ServerBuilder builder;
            builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
            builder.RegisterService(&service);
            std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
            logger::log(logger::INFO) << "Server listening on " << server_address << std::endl;
            
            *server_ptr = server.get();
            
            //service.print_stats(sse::logger::log(sse::logger::INFO));
            service.set_search_asynchronously(async_search);
            
            server->Wait();
        }

    }
}
