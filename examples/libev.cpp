/**
 *  LibEV.cpp
 * 
 *  Test program to check AMQP functionality based on LibEV
 * 
 *  @author Emiel Bruijntjes <emiel.bruijntjes@copernica.com>
 *  @copyright 2015 - 2018 Copernica BV
 */

/**
 *  Dependencies
 */
#include <ev.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <iostream>
#include <fstream>
#include <amqpcpp.h>
#include <amqpcpp/libev.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>


int getp12(std::string filename, std::string pass, EVP_PKEY **pkey, X509 **cert, X509 **ca)
{
    FILE *fp;
    STACK_OF(X509) *cas = NULL;
    
    
    PKCS12 *p12;
    int i;
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!(fp = fopen(filename.c_str(), "rb"))) {
        fprintf(stderr, "Error opening file %s\n", filename.c_str());
        return -1;
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if (!p12) {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!PKCS12_parse(p12, pass.c_str(), pkey, cert, &cas)) {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    PKCS12_free(p12);

/* No need to write to files!
    if (*pkey) {
        fp = fopen("key.pem", "w");
        PEM_write_PrivateKey(fp, *pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fp);    
    }
    if (*cert) {
        fp = fopen("cert.pem", "w");
        PEM_write_X509_AUX(fp, *cert);
        fclose(fp); 
    }

    if (cas && sk_X509_num(cas)) {
        fp = fopen("chain.pem", "w");
        for (i = 0; i < sk_X509_num(cas); i++) 
            PEM_write_X509_AUX(fp, sk_X509_value(cas, i));
        fclose(fp); 
    }

*/
    //ca=sk_X509_value(cas, 0);

    
    

    sk_X509_pop_free(cas, X509_free);
    //X509_free(cert);
    //EVP_PKEY_free(pkey);

    
    return 0;
}

/**
 *  Custom handler
 */
class MyHandler : public AMQP::LibEvHandler
{
private:
    /**
     *  Method that is called when a connection error occurs
     *  @param  connection
     *  @param  message
     */
    virtual void onError(AMQP::TcpConnection *connection, const char *message) override
    {
        std::cout << "error: " << message << std::endl;
    }

    /**
     *  Method that is called when the TCP connection ends up in a connected state
     *  @param  connection  The TCP connection
     */
    virtual void onConnected(AMQP::TcpConnection *connection) override 
    {
        std::cout << "connected" << std::endl;
    }

    /**
     *  Method that is called when the TCP connection ends up in a ready
     *  @param  connection  The TCP connection
     */
    virtual void onReady(AMQP::TcpConnection *connection) override 
    {
        std::cout << "ready" << std::endl;
    }

    /**
     *  Method that is called when the TCP connection is closed
     *  @param  connection  The TCP connection
     */
    virtual void onClosed(AMQP::TcpConnection *connection) override 
    {
        std::cout << "closed" << std::endl;
    }

    /**
     *  Method that is called when the TCP connection is detached
     *  @param  connection  The TCP connection
     */
    virtual void onDetached(AMQP::TcpConnection *connection) override 
    {
        std::cout << "detached" << std::endl;
    }

    virtual bool onSSLCreated(AMQP::TcpConnection *connection, const SSL *ssl) override
    {
        std::cout<<"onSSLCreated"<<std::endl;
        std::cout << "load pkey=" << SSL_use_PrivateKey((SSL*)ssl, mpkey) << std::endl;
        std::cout << "load cert=" << SSL_use_certificate((SSL*)ssl, mcert) << std::endl;
        //std::cout << "load ca=" <<SSL_add0_chain_cert((SSL *)ssl, mca) << std::endl;

        return true;
    }

    virtual bool onSecured(AMQP::TcpConnection *connection, const SSL *ssl) override
    {
        std::cout<<"onSecured"<<std::endl;
        // @todo
        //  add your own implementation, for example by reading out the
        //  certificate and check if it is indeed yours
        return true;
    }

    EVP_PKEY *mpkey;
    X509 *mcert;
    //STACK_OF(X509) *ca;
    X509 *mca;
    
public:
    /**
     *  Constructor
     *  @param  ev_loop
     */
    MyHandler(struct ev_loop *loop, EVP_PKEY *pkey, X509 *cert, X509 *ca) : AMQP::LibEvHandler(loop) {
        mpkey=pkey;
        mcert=cert;
        mca=ca;
    }

    /**
     *  Destructor
     */
    virtual ~MyHandler() = default;
};

/**
 *  Class that runs a timer
 */
class MyTimer
{
private:
    /**
     *  The actual watcher structure
     *  @var struct ev_io
     */
    struct ev_timer _timer;

    /**
     *  Pointer towards the AMQP channel
     *  @var AMQP::TcpChannel
     */
    AMQP::TcpChannel *_channel;

    /**
     *  Name of the queue
     *  @var std::string
     */
    std::string _queue;


    /**
     *  Callback method that is called by libev when the timer expires
     *  @param  loop        The loop in which the event was triggered
     *  @param  timer       Internal timer object
     *  @param  revents     The events that triggered this call
     */
    static void callback(struct ev_loop *loop, struct ev_timer *timer, int revents)
    {
        // retrieve the this pointer
        MyTimer *self = static_cast<MyTimer*>(timer->data);

        // publish a message
        self->_channel->publish("", self->_queue, "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

public:
    /**
     *  Constructor
     *  @param  loop
     *  @param  channel
     *  @param  queue
     */
    MyTimer(struct ev_loop *loop, AMQP::TcpChannel *channel, std::string queue) : 
        _channel(channel), _queue(std::move(queue))
    {
        // initialize the libev structure
        ev_timer_init(&_timer, callback, 0.005, 1.005);

        // this object is the data
        _timer.data = this;

        // and start it
        ev_timer_start(loop, &_timer);
    }
    
    /**
     *  Destructor
     */
    virtual ~MyTimer()
    {
        // @todo to be implemented
    }
};


/**
 *  Main program
 *  @return int
 */
int main(int argc, char **argv)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509 *ca = NULL;
    //STACK_OF(X509) *ca = NULL;

    //load the p12
    getp12(argv[1],argv[2], &pkey, &cert, &ca);

    // access to the event loop
    auto *loop = EV_DEFAULT;
    
    // handler for libev
    MyHandler handler(loop, pkey, cert, ca);

    // init the SSL library
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    // make a connection
    AMQP::Address address("amqps://ec2-3-121-224-144.eu-central-1.compute.amazonaws.com/");
//    AMQP::Address address("amqps://guest:guest@localhost/");
    AMQP::TcpConnection connection(&handler, address);
    
    // we need a channel too
    AMQP::TcpChannel channel(&connection);

    // create a temporary queue
    channel.declareQueue(AMQP::exclusive).onSuccess([&connection, &channel, loop](const std::string &name, uint32_t messagecount, uint32_t consumercount) {
        
        // report the name of the temporary queue
        std::cout << "declared queue " << name << std::endl;
        
        // close the channel
        //channel.close().onSuccess([&connection, &channel]() {
        //    
        //    // report that channel was closed
        //    std::cout << "channel closed" << std::endl;
        //    
        //    // close the connection
        //    connection.close();
        //});
        
        // construct a timer that is going to publish stuff
        auto *timer = new MyTimer(loop, &channel, name);
        
        //connection.close();
    });
    
    // run the loop
    ev_run(loop, 0);

    // done
    return 0;
}

