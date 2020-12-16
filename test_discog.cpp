//
//  test_diana
//  diana
//
//  Created by Raphael Bost on 19/07/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

// test for discog, created by Xiangfu Song

#include <iostream>
#include <fstream>
#include <memory>

#include "discog/discog_client.hpp"
#include "discog/discog_server.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"

using namespace sse::discog;
using namespace std;

void test_client_server()
{
    sse::logger::set_severity(sse::logger::DBG);
    
    // string client_main_path = "test_discog_client", server_main_path = "test_discog_server";
    string client_master_key_path = "discog_derivation_master.key";
    string client_kw_token_master_key_path = "discog_kw_token_master.key";
    string counter_path = "global_counter.dat";
    string server_path =  "discog_server.dat";

    
    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream client_kw_token_master_key_in(client_kw_token_master_key_path.c_str());
    
    typedef uint64_t index_type;
    
    unique_ptr<DiscogClient<index_type>> client;
    unique_ptr<DiscogServer<index_type>> server;
    
    SearchRequest s_req;
    UpdateRequest<index_type> u_req;
    std::list<index_type> res;
    string key;

    if((client_kw_token_master_key_in.good() != client_master_key_in.good()) )
    {
        client_master_key_in.close();
        client_kw_token_master_key_in.close();

        throw std::runtime_error("All streams are not in the same state");
    }
    
    if (client_master_key_in.good() == true) {
        // the files exist
        cout << "Restart Discog client and server" << endl;
        
        stringstream client_master_key_buf, client_kw_token_key_buf;

        client_master_key_buf << client_master_key_in.rdbuf();
        client_kw_token_key_buf << client_kw_token_master_key_in.rdbuf();

        client.reset(new  DiscogClient<index_type>(counter_path, client_master_key_buf.str(), client_kw_token_key_buf.str(), 1));
        client->increase_global_counter();
        
        server.reset(new DiscogServer<index_type>(server_path));
        
        SearchRequest s_req;
        std::list<index_type> res;
        string key;

    }else{
        cout << "Create new Discog client-server instances" << endl;
        
        client.reset(new DiscogClient<index_type>(counter_path));
        client->increase_global_counter();

        server.reset(new DiscogServer<index_type>(server_path, 1000));
        
        // write keys to files
        
        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << client->master_derivation_key();
        client_master_key_out.close();

        ofstream client_kw_token_master_key_out(client_kw_token_master_key_path.c_str());
        client_kw_token_master_key_out << client->kw_token_master_key();
        client_kw_token_master_key_out.close();


        
        for (uint32_t ind = 0; ind < 10; ind++)
        {
            u_req = client->update_request("toto", ind);
            server->update(u_req);
        }
        
//        u_req = client->update_request("titi", 0);
//        server->update(u_req);
        
        //u_req = client->update_request("toto", 1);
        //server->update(u_req);
        
        //u_req = client->update_request("toto", 2);
        //server->update(u_req);
        
//        u_req = client->update_request("tata", 0);
//        server->update(u_req);
        

    }
    

    
    key = "toto";
    s_req = client->search_request(key);
//    res = server->search(s_req);
    res = server->search(s_req);

    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

//    key = "titi";
//    s_req = client->search_request(key);
//    res = server->search(s_req);
//    
//    cout << "Search " << key << ". Results: [";
//    for(index_type i : res){
//        cout << i << ", ";
//    }
//    cout << "]" << endl;
//
//    key = "tata";
//    s_req = client->search_request(key);
//    res = server->search(s_req);
//    
//    cout << "Search " << key << ". Results: [";
//    for(index_type i : res){
//        cout << i << ", ";
//    }
//    cout << "]" << endl;

    client_master_key_in.close();
    client_kw_token_master_key_in.close();

}

int main(int argc, const char * argv[]) {

    test_client_server();
    
    return 0;
}
