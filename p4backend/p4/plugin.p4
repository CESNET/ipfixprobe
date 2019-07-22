/*
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

 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
*/

#ifndef _PLUGIN_P4_
#define _PLUGIN_P4_

extern payload
{
   // Parse strings to variables, move payload cursor to end of the matched position (if method returns true)
   // Variable assignment is specified by capturing strings with capture groups ()
   // For example when using this @regex("(\"GET\"|\"POST\")[ ]([^ ]*)[ ]\"HTTP\"[/][0-9][.][0-9]\"\r\n\""),
   // method call parse(regex, {method, uri}) will place matched 'GET' or 'POST' string in `method` variable and so on
   // Format of regular expression can be found here http://re2c.org/manual/syntax/syntax.html
   bool extract_re<R, V>(in R regex, in V vars);

   // Check if payload matches given regex without consuming input (start from current payload cursor)
   bool lookahead_re<R>(in R regex);

   // Check if string matches regex
   bool match<R, V>(in R regex, in V str);
   // Copy string
   void strcpy<S1, S2>(in S1 dst, in S2 src);
   // Convert string to number
   void to_number<N, S>(in S str, out N number);

   // Extract bits
   void extract<T>(out T var);

   // Extract variable length bits (strings)
   void extract_string<T>(out T var, in bit<32> length);

   // Extract bits without consuming input
   T lookahead<T>();

   // Skip bytes
   void advance(in bit<32> bytes);

   // Get number of bytes left in current payload
   bit<32> length();
}

#endif