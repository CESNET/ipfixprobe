/**
 * \file ipfix-basiclist.cpp
 * \brief Plugin representing ipfix basiclist fmt.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */


#include <ipfixprobe/ipfix-basiclist.hpp>

namespace ipxp {

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, uint16_t *values, uint16_t len, uint16_t fieldID)
{
   int32_t written = this->FillBufferHdr(buffer, len, sizeof(uint16_t), fieldID);

   for (int i = 0; i < len; i++) {
      (*reinterpret_cast<uint16_t *>(buffer + written)) = htons(values[i]);
      written += sizeof(uint16_t);
   }
   return written;
}

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, int16_t *values, uint16_t len, uint16_t fieldID)
{
   return this->FillBuffer(buffer, (uint16_t *) values, len, fieldID);
}

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, uint32_t *values, uint16_t len, uint16_t fieldID)
{
   int32_t written = this->FillBufferHdr(buffer, len, sizeof(uint32_t), fieldID);

   for (int i = 0; i < len; i++) {
      (*reinterpret_cast<uint32_t *>(buffer + written)) = htonl(values[i]);
      written += sizeof(uint32_t);
   }
   return written;
}

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, int32_t *values, uint16_t len, uint16_t fieldID)
{
   return this->FillBuffer(buffer, (uint32_t *) values, len, fieldID);
}

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, struct timeval *values, uint16_t len, uint16_t fieldID)
{
   int32_t written = this->FillBufferHdr(buffer, len, sizeof(uint64_t), fieldID);

   for (int i = 0; i < len; i++) {
      (*reinterpret_cast<uint64_t *>(buffer + written)) = swap_uint64(Tv2Ts(values[i]));
      written += sizeof(uint64_t);
   }
   return written;
}

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, uint8_t *values, uint16_t len, uint16_t fieldID)
{
   int32_t written = this->FillBufferHdr(buffer, len, sizeof(uint8_t), fieldID);

   memcpy(buffer + written, values, len);
   written += len;
   return written;
}

int32_t IpfixBasicList::FillBuffer(uint8_t *buffer, int8_t *values, uint16_t len, uint16_t fieldID)
{
   return this->FillBuffer(buffer, (uint8_t *) values, len, fieldID);
}

int32_t IpfixBasicList::FillBufferHdr(uint8_t *buffer, uint16_t length, uint16_t elementLength, uint16_t fieldID)
{
   uint32_t bufferPtr = 0;

   // Copy flag
   buffer[bufferPtr] = flag;
   bufferPtr        += sizeof(uint8_t);
   // Copy length;
   *(reinterpret_cast<uint16_t *>(buffer + bufferPtr)) = htons(IpfixBasicListHdrSize + length * elementLength);
   bufferPtr += sizeof(uint16_t);
   // copy hdr_semantic
   buffer[bufferPtr] = hdrSemantic;
   bufferPtr        += sizeof(uint8_t);
   // copy hdr_field_id
   *(reinterpret_cast<uint16_t *>(buffer + bufferPtr)) = htons((1 << 15) | fieldID);
   bufferPtr += sizeof(uint16_t);
   // copy hdr_element_len
   *(reinterpret_cast<uint16_t *>(buffer + bufferPtr)) = htons(elementLength);
   bufferPtr += sizeof(uint16_t);
   // copy enterprise num from hdr struct
   *(reinterpret_cast<uint32_t *>(buffer + bufferPtr)) = htonl((uint32_t) hdrEnterpriseNum);
   bufferPtr += sizeof(uint32_t);

   return bufferPtr;
}

int32_t IpfixBasicList::HeaderSize()
{
   return IpfixBasicListRecordHdrSize;
}

uint64_t IpfixBasicList::Tv2Ts(timeval input)
{
   return static_cast<uint64_t>(input.tv_sec) * 1000 + (input.tv_usec / 1000);
}

}
