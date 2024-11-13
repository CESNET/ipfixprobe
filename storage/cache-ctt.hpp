#ifndef IPXP_STORAGE_CACHE_CTT_HPP
#define IPXP_STORAGE_CACHE_CTT_HPP

#include "cache.hpp"
#include "ctt-controller.hpp"

namespace ipxp {

// Extend CacheOptParser to create CacheCTTOptParser
class CacheCTTOptParser : public CacheOptParser
{
public:
   std::string m_dev;

   CacheCTTOptParser() : CacheOptParser(), m_dev("")
   {
      // Register the new option "dev=DEV for device name where is CTT running"
      register_option("d", "dev", "DEV", "Device name",
         [this](const char *arg){
            m_dev = arg;
            return true;
         },
         OptionFlags::RequiredArgument);
   }
};

class NHTFlowCacheCTT : public NHTFlowCache
{
public:
   NHTFlowCacheCTT();
   ~NHTFlowCacheCTT();

   void init(const char *params) override;
   OptionsParser *get_parser() const override { return new CacheCTTOptParser(); }
   std::string get_name() const override { return "cache_ctt"; }

   // override post_create method
   int plugins_post_create(Flow &rec, Packet &pkt) {
      int ret = StoragePlugin::plugins_post_create(rec, pkt);
      if (no_data_required(rec)) {
         m_ctt_controller.create_record(rec.flow_hash_ctt, rec.time_first);
      } else if (all_data_required(rec)) {
         m_ctt_controller.create_record(rec.flow_hash_ctt, rec.time_first);
      }


      return ret;
   }

private:
   std::string m_dev;
   CttController m_ctt_controller;
};

}

#endif /* IPXP_STORAGE_CACHE_CTT_HPP */