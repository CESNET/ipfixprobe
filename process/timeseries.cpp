/**
 * \file timeseries.cpp
 * \brief Plugin for parsing timeseries traffic.
 * \author David Kezlinek
 * \date 2023
 */
/*
 * Copyright (C) 2023 CESNET
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
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
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
 *
 */

#include <iostream>
#include "timeseries.hpp"

namespace ipxp {

    std::vector<std::pair<uint16_t, uint16_t>> PacketLengthsArray::getHistogram() const{
        uint16_t Hist[1501] = {0};
        for (size_t i = 0; i < m_packet_lengths.size(); i++){
            Hist[m_packet_lengths[i]]++;
        }
        std::vector<std::pair<uint16_t, uint16_t>> Histogram;
        if (m_packet_lengths.size() < 1500){
            Histogram.reserve(m_packet_lengths.size());
        }
        else{
            Histogram.reserve(1500);
        }
        for (size_t i = 0; i <= 1500; i++)
        {
            if (Hist[i] != 0)
            {
                Histogram.push_back(std::pair<uint16_t, uint16_t>(i, Hist[i]));
            }
        }
        Histogram.shrink_to_fit();
        return Histogram;
    }


    PacketLengthsHistogram::PacketLengthsHistogram(PacketLengthsSmall *tmp, uint16_t PacketLength){
        m_Histogram[tmp->get_bin(0)] = tmp->get_frequency(0);
        m_Histogram[tmp->get_bin(1)] = tmp->get_frequency(1);
        m_Histogram[PacketLength] = 1;
        m_packet_count = tmp->get_frequency(0) + tmp->get_frequency(1) + 1;
        m_flow_size = tmp->get_bin(0) + tmp->get_bin(1) + PacketLength;
    }

    std::vector<std::pair<uint16_t, uint16_t>> PacketLengthsHistogram::getHistogram() const{
        std::vector<std::pair<uint16_t, uint16_t>> Histogram;
        Histogram.reserve(1500);

        for (size_t i = 0; i <= 1500; i++)
        {
            if (m_Histogram[i] != 0)
            {
                Histogram.push_back(std::pair<uint16_t, uint16_t>(i, m_Histogram[i]));
            }
        }
        Histogram.shrink_to_fit();
        return Histogram;
    }

    bool inline PacketLengthsSmall::add(uint16_t PacketLength){

        if (m_unique_count == 1){ 
            if (PacketLength == m_bin[0]){
                m_frequency[0]++;
                return (m_frequency[0] >= MAX_PACKETS_HISTOGRAM);
            }
            else{
                if (PacketLength < m_bin[0]){
                    m_bin[1] = m_bin[0];
                    m_frequency[1] = m_frequency[0];
                    m_bin[0] = PacketLength;
                    m_frequency[0] = 1;
                }
                else{
                    m_bin[1] = PacketLength;
                    m_frequency[1] = 1;
                }
                m_unique_count++;
            }
        }
        else if (m_unique_count == 2)
        {
            for (uint8_t i = 0; i < 2; ++i)
            {
                if (m_bin[i] == PacketLength)
                {
                    m_frequency[i]++;
                    return ((m_frequency[0] + m_frequency[1]) >= MAX_PACKETS_HISTOGRAM);;
                }
            }
            PacketLengthsSmall *tmp = this;
            m_record->SizeData = new PacketLengthsHistogram(tmp, PacketLength);
            delete tmp;

            return false;
        }
        else if (m_unique_count == 0)
        {
            m_bin[0] = PacketLength;
            m_frequency[0] = 1;
            m_unique_count = 1;
        }
        
        return ((m_frequency[0] + m_frequency[1]) >= MAX_PACKETS_HISTOGRAM);
    }
    
    std::vector<std::pair<uint16_t, uint16_t>> PacketLengthsSmall::getHistogram() const{
        std::vector<std::pair<uint16_t, uint16_t>> Histogram;
        Histogram.reserve(m_unique_count);

        for (size_t i = 0; i < m_unique_count; i++)
        {
            Histogram.push_back(std::pair<uint16_t, uint16_t>(m_bin[i], m_frequency[i]));
        }
        Histogram.shrink_to_fit();
        return Histogram;
    }


    TS_time_result *PacketTimes::calculateTime() const{
    
        TS_time_result *Result = new TS_time_result;
        if (m_time_data.size() > 0)
        {
            if (m_time_data[m_time_data.size() - 1] != 0){
                Result->TS_MEDIAN_SCALED_TIME = (float)m_time_data[(m_time_data.size()) / 2]/ m_time_data[m_time_data.size() - 1];
                Result->TS_Q1_SCALED_TIME = (float)m_time_data[(m_time_data.size()) / 4]/ m_time_data[m_time_data.size() - 1];
                Result->TS_Q3_SCALED_TIME = (float)m_time_data[3 * (m_time_data.size()) / 4]/ m_time_data[m_time_data.size() - 1];
            }
            Result->TS_DURATION = m_time_data[m_time_data.size() - 1];
            std::vector<uint32_t> difftimes(m_time_data.size() - 1);
            uint64_t meanTime = 0;
            uint64_t meanDifftimes = 0;
            if(m_time_data.size() >= 2)
                Result->TS_MIN_DIFFTIMES =m_time_data[1] - m_time_data[0];

            for (int i = 0; i < (int)m_time_data.size() - 1; i++){
                meanTime += m_time_data[i];
                difftimes[i] = m_time_data[i + 1] - m_time_data[i];
                meanDifftimes += difftimes[i];
                if (difftimes[i] > Result->TS_MAX_DIFFTIMES){
                    Result->TS_MAX_DIFFTIMES = difftimes[i];
                }
                if (difftimes[i] < Result->TS_MIN_DIFFTIMES){
                    Result->TS_MIN_DIFFTIMES = difftimes[i];
                }
            }
            meanTime += m_time_data[m_time_data.size() - 1];

            if (m_time_data[m_time_data.size() - 1] != 0)
                Result->TS_MEAN_SCALED_TIME = ((float)meanTime / m_time_data.size()) / m_time_data[m_time_data.size() - 1];
            if (m_time_data.size() < 2)
            {
                Result->TS_TIME_DISTRIBUTION = 0.5;
                return Result;
            }

            Result->TS_MEAN_DIFFTIMES = (double)meanDifftimes / (m_time_data.size() - 1);
            uint64_t yDT = 0;
            double kurtosis =0;
            double var =0;
            for (size_t i = 0; i < difftimes.size(); i++)
            {
                yDT += std::abs(Result->TS_MEAN_DIFFTIMES - difftimes[i]);
                var += pow(difftimes[i] - Result->TS_MEAN_DIFFTIMES,2);
                kurtosis += pow(difftimes[i] - Result->TS_MEAN_DIFFTIMES,4);
            }
            var /= difftimes.size();
            if(var != 0)
                Result->TS_DIFFTIMES_KURTOSIS = kurtosis / (difftimes.size() *var *var);
            
            if(Result->TS_MAX_DIFFTIMES != Result->TS_MIN_DIFFTIMES) 
                Result->TS_TIME_DISTRIBUTION = ((float)yDT / difftimes.size()) / ((float)(Result->TS_MAX_DIFFTIMES - Result->TS_MIN_DIFFTIMES) / 2);

            
            std::nth_element(difftimes.begin(), difftimes.begin() + difftimes.size() / 2 +1, difftimes.end());
            Result->TS_MEDIAN_DIFFTIMES = difftimes[difftimes.size() / 2];

            var = sqrt(var);
            if(var != 0)
                Result->TS_DIFFTIMES_SKEWNESS = (3*Result->TS_MEAN_DIFFTIMES - Result->TS_MEDIAN_DIFFTIMES) / var;

        }
        return Result;
    }







int RecordExtTIMESERIES::REGISTERED_ID = -1;
bool RecordExtTIMESERIES::IPFIXSetuped=false;
char * RecordExtTIMESERIES::ipfix_template[100];


    bool RecordExtTIMESERIES::calculateResult(){
    if(Result == nullptr){
        Result =new TS_results;
    }else{
        return false;
    }
    if(Time){
        if(TimeData == nullptr)
            return false;

        Result->time = TimeData->calculateTime();
    }
    if (SizeData == nullptr){  
        return true;
    }
    
    auto histogram = SizeData->getHistogram();
    if (Statistics)
        Result->statistics = calculateStatistics(histogram);

    if(Behavior){
        if(TimeData == nullptr || useHistogram())
            return false;
        Result->behavior = calculateBehavior(TimeData->getTimeValues(),((PacketLengthsArray *)SizeData)->getSizeValues(), histogram);
    }
    if(Frequency){
        if(TimeData == nullptr || useHistogram())
            return false;
        Result->frequency = calculateFrequency(TimeData->getTimeValues(),((PacketLengthsArray *)SizeData)->getSizeValues());
    }


    return true;
  }


void RecordExtTIMESERIES::nfft(const double *t, const double *y,
          int n, int m, double _Complex *d)const{
    // Creates NFFT plan for 2*m Fourier
    // coefficients (positive and negative
    // frequencies ) and n data samples.
    nfft_plan p;
    nfft_init_1d(&p, 2 * m, n);

    if (y != NULL) // data spectrum
    {
        for (int i = 0; i < n; i++)
        {
            p.x[i] = t[i];
            p.f[i][0] = y[i];
            p.f[i][1] = 0.0;
        }
    }
    else // window spectrum
    {
        for (int i = 0; i < n; i++)
        {
            p.x[i] = t[i];
            p.f[i][0] = 1.0;
            p.f[i][1] = 0.0;
        }
    }

    // Possibly optimises.
    if (p.flags & PRE_ONE_PSI)
        nfft_precompute_one_psi(&p);

    // Computes the adjoint transform.
    nfft_adjoint(&p);

    // Outputs the positive frequency
    // Fourier coefficients .
    for (int i = 0; i < m; i++)
    {
        d[i] = p.f_hat[i][0] + p.f_hat[i][1] * I;
    }
    d[m] = p.f_hat[0][0] - p.f_hat[0][1] * I;

    // d[m] = conj(p.f_hat[0]);

    nfft_finalize(&p);

}

RecordExtTIMESERIES::LS *RecordExtTIMESERIES::periodogram(const double *t, const double *y, int npts, double over, double hifac, double var)const{
    double df = 1.0 / (over * (t[npts - 1] - t[0]));

    // Index of the highest frequency in the positive frequency part of spectrum.
    int m = floor(0.5 * npts * over * hifac);

    LS *ls = new LS(m);

    // Unnormalised FTs of the data and window.
    double _Complex *sp = (double _Complex *)malloc((m + 1) * sizeof(double _Complex));

    nfft(t, y, npts, m, sp);

    double _Complex *win = (double _Complex *)malloc((2 * (m + 1)) * sizeof(double _Complex));
    nfft(t, NULL, npts, 2 * m, win);

    // Computes the periodogram ordinates,
    // and store the results in the LS structure.
    for (int j = 1; j <= m; j++){
        double _Complex z1 = sp[j];      // FT of data at \omega
        double _Complex z2 = win[2 * j]; // FT of window at 2\omega
        double absz2 = cabs(z2);
        double hc2wt = 0.5 * cimag(z2) / absz2;
        double hs2wt = 0.5 * creal(z2) / absz2;
        double cwt = sqrt(0.5 + hc2wt);
        double swt = sign(sqrt(0.5 - hc2wt), hs2wt);
        double den = 0.5 * npts + hc2wt * creal(z2) + hs2wt * cimag(z2);
        double cterm = square(cwt * creal(z1) + swt * cimag(z1)) / den;
        double sterm = square(cwt * cimag(z1) - swt * creal(z1)) / (npts - den);
        ls->freqs[m - j] = (j - 1) * df * df;
        ls->Pn[j - 1] = (cterm + sterm) / var / npts;
    }

    free(win);
    free(sp);
    return ls;
}

RecordExtTIMESERIES::LS * RecordExtTIMESERIES::computePeriodogram(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value, double oversampling_factor, double highest_freq_factor)const{
    // Lenght of TimeSesries
    int npts = time.size();

    // 2. Compute the mean and the variance of the data.
    //  Calculate the mean
    double mean_value = 0.0;
    double var = 0.0;

    if (Result->statistics != nullptr)
    {
        mean_value = Result->statistics->TS_MEAN;
        var = Result->statistics->TS_VAR;
    }else{
        for (int i = 0; i < npts; i++){
            mean_value += value[i];
        }
        mean_value /= npts;
        // Calculate the var
            
        for (int i = 0; i < (int)value.size(); i++){
            var += pow(value[i] - mean_value, 2);
        }
        var /= value.size();
    }
    
    // 3. Center the measurements around the mean
    std::vector<double> y(npts);
    for (int i = 0; i < npts; i++){
        y[i] = value[i] - mean_value;
    }

    // 4. Reduce the time span to the interval [-1/2, 1/2) using the transformation ti � xi = 2a(ti � t1)�f � a     (32)
    double t1 = (double)time[0];

    double tNt = (double)time[npts - 1];
    double delta_f = 1.0 / (oversampling_factor * (tNt - t1)); //        (30)
    double a = 0.5 - 0.00001;
    std::vector<double> x(npts);
    for (int i = 0; i < npts; i++){
        x[i] = (2.0 * a * ((double)time[i] - t1) * delta_f) - a; //        (32)
    }


    // double nyquist_freq = (npts ) / (2 * (tNt - t1) );
    // double highest_freq = highest_freq_factor * nyquist_freq;
    return periodogram(x.data(), y.data(), npts, oversampling_factor, highest_freq_factor, var);
}



double RecordExtTIMESERIES::PolyFit1D(const double *x_data, const double *y_data, const size_t size, const double x_mean, const double y_mean)const{
    double numerator = 0;
    double denominator = 0;
    for (size_t i = 0; i < size; ++i){
        numerator += (x_data[i] - x_mean) * (y_data[i] - y_mean);
        denominator += (x_data[i] - x_mean) * (x_data[i] - x_mean);
    }

    // double slope = numerator / denominator;
    // double intercept = y_mean - slope * x_mean;
    return numerator / denominator;
}

double RecordExtTIMESERIES::PolyFit1D(const double *x_data, const double *y_data, const size_t size)const{
    double x_mean = 0;
    double y_mean = 0;
    for (size_t i = 0; i < size; ++i){
        x_mean += x_data[i];
        y_mean += y_data[i];
    }
    x_mean /= (double)size;
    y_mean /= (double)size;
    return PolyFit1D(x_data, y_data, size, x_mean, y_mean);
}

double RecordExtTIMESERIES::LogPolyFit1D(const double *x_data, const double *y_data, const size_t size)const{
    double x_mean = 0;
    double y_mean = 0;
    size_t truesize = size;

    for (size_t i = 0; i < size; ++i){
        if (x_data[i] == 0 || y_data[i] == 0){
            truesize--;
            continue;
        }
        if (x_data[i] != 0)
            x_mean += log(x_data[i]);
        
        
        if (y_data[i] != 0)
            y_mean += log(y_data[i]);
    }
    x_mean /= (double)truesize;
    y_mean /= (double)truesize;

    double numerator = 0;
    double denominator = 0;
    double logx =0, logy =0;

    for (size_t i = 0; i < size; ++i){
        if (x_data[i] == 0 || y_data[i] == 0){
            continue;
        }
        if (x_data[i] != 0)
            logx = log(x_data[i]);
        if (y_data[i] != 0)
            logy = log(y_data[i]);

        numerator += (logx - x_mean) * (logy - y_mean);
        denominator += (logx - x_mean) * (logx - x_mean);
    }

    // double slope = numerator / denominator;
    // double intercept = y_mean - slope * x_mean;
    return numerator / denominator;
}

double RecordExtTIMESERIES::calculateHurstExponent(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value)const
{
    if (time.size() <= 1)
        return 0.5;
    if(time[time.size()-1] == 0)
        return 0.5;
    std::vector<double> log_ns;
    std::vector<double> log_R_Ss_bytes;
    int N = (int)value.size();
    for (int i = 1; (i < 5) && (i < N); i++){
        int n = N / i;
        if (n == 0)
            break;
        double RS = 0;
        for (int k = 0; k < N / n; ++k){
            double mean = 0;

            for (int j = k * n + 1; j < (k + 1) * n; ++j)
            {
                mean += value[j] * (time[j] - time[j - 1]);
            }
            if ((time[(k + 1) * n - 1] - time[k * n]) == 0)
                continue;
            mean /= (time[(k + 1) * n - 1] - time[k * n]);
            double min = (value[k * n + 1] - mean) * (time[k * n + 1] - time[k * n]);
            double max = min;
            double Xn = 0;
            double S = 0;

            for (int j = k * n + 1; j < (k + 1) * n; ++j)
            {
                Xn += (value[j] - mean) * (time[j] - time[j - 1]);
                S += (value[j] - mean) * (value[j] - mean) * (time[j] - time[j - 1]);
                if (Xn < min)
                {
                    min = Xn;
                }
                else if (Xn > max)
                {
                    max = Xn;
                }
            }
            S /= (time[(k + 1) * n - 1] - time[k * n]);
            S = std::sqrt(S);
            if (S == 0){
                continue;
            }
            RS += (max - min) / S;
        }
        RS /= (N / n);
        if (RS == 0)
            continue;
        double E_R_S = 0;
        for (int j = 1; j < n; ++j)
        {
            E_R_S += (float)(n - j) / j;
        }
        if (n > 340)
        {
            E_R_S /= sqrt(((double)n * M_PI) / 2);
        }
        else
        {
            E_R_S *= (std::tgamma(((double)n - 1) / 2)) / (std::sqrt(n) * std::tgamma((double)n / 2));
        }
        log_ns.push_back(n);
        log_R_Ss_bytes.push_back(std::abs(RS - E_R_S));
    }

    return 0.5 + PolyFit1D(log_ns.data(), log_R_Ss_bytes.data(), log_ns.size());
}

double RecordExtTIMESERIES::calculateHurstExponent(const std::vector<uint16_t> &data)const
{
    int N = (int)data.size();
    std::vector<double> log_ns;
    std::vector<double> log_R_Ss_bytes;

    for (int i = 1; (i < 5) && (i < N); i++){
        int n = N / i;
        if (n == 0)
            break;
        double RS = 0;
        for (int k = 0; k < N / n; ++k){
            float mean = 0;

            for (int j = k * n; j < (k + 1) * n; ++j){
                mean += data[j];
            }

            mean /= n;
            double min = (data[k * n] - mean);
            double max = min;
            double Xn = 0;
            double S = 0;
            for (int j = k * n; j < (k + 1) * n; ++j){
                Xn += (data[j] - mean);
                S += (data[j] - mean) * (data[j] - mean);
                if (Xn < min){
                    min = Xn;
                }
                else if (Xn > max){
                    max = Xn;
                }
            }
            S /= n;
            S = std::sqrt(S);
            if (S == 0){
                continue;
            }
            RS += (max - min) / S;
        }
        RS /= (N / n);
        if (RS == 0)
            continue;
        double E_R_S = 0;
        for (int j = 1; j < n; ++j){
            E_R_S += ((float)n - j) / j;
        }
        if (n > 340){
            E_R_S /= sqrt(((double)n * M_PI) / 2);
        }
        else{
            E_R_S *= (std::tgamma(((double)n - 1) / 2)) / (std::sqrt(n) * std::tgamma((double)n / 2));
        }
        log_ns.push_back(n);
        log_R_Ss_bytes.push_back(std::abs(RS - E_R_S));
    }
    if(log_ns.size() <= 1){
        return 0.5;
    }

    return (PolyFit1D(log_ns.data(), log_R_Ss_bytes.data(), log_ns.size()) + 0.5);
}

TS_statistics_result *RecordExtTIMESERIES::calculateStatistics(const std::vector<std::pair<uint16_t, uint16_t>> &Histogram)const{ 
    uint16_t TotalPacketCount= SizeData->getPacketCount();
    uint32_t FlowSize =SizeData->getFlowSize();
    TS_statistics_result *res = new TS_statistics_result;
    if (TotalPacketCount == 0 || Histogram.size() == 0){
        return res;
    }

    double Mean = (double)FlowSize / TotalPacketCount;
    res->TS_MEAN = (float)FlowSize / TotalPacketCount;
    int i = 0;
    uint32_t sum = 0;
    double var = 0, rms = 0, fisher_3 = 0, kurtosis = 0, avg_disp = 0, entropy = 0;
    uint16_t ModeCount = 0;

    for (i = 0; sum <= (TotalPacketCount) / 4 && i < (int)Histogram.size(); i++) // find Q1
    {
        if (Histogram[i].second != 0){
            sum += Histogram[i].second;
            var += Histogram[i].second * std::pow(Histogram[i].first - Mean, 2);
            avg_disp += Histogram[i].second * std::abs(Histogram[i].first - Mean);
            rms += Histogram[i].second * (Histogram[i].first * Histogram[i].first);
            fisher_3 += ((float)Histogram[i].second / TotalPacketCount) * pow(Histogram[i].first, 3);
            kurtosis += Histogram[i].second * pow(Histogram[i].first - Mean, 4);
            entropy -= ((float)Histogram[i].second / TotalPacketCount) * log2((float)Histogram[i].second / TotalPacketCount);
            if (Histogram[i].second > ModeCount){
                res->TS_MODE = Histogram[i].first;
                ModeCount = Histogram[i].second;
            }
        }
    }
    res->TS_Q1 = Histogram[i - 1].first;
    for (; sum <= (TotalPacketCount) / 2 && i < (int)Histogram.size(); i++) // find Median
    {
        if (Histogram[i].second != 0){
            sum += Histogram[i].second;
            var += Histogram[i].second * std::pow(Histogram[i].first - Mean, 2);
            avg_disp += Histogram[i].second * std::abs(Histogram[i].first - Mean);
            rms += Histogram[i].second * (Histogram[i].first * Histogram[i].first);
            fisher_3 += ((float)Histogram[i].second / TotalPacketCount) * pow(Histogram[i].first, 3);
            kurtosis += Histogram[i].second * pow(Histogram[i].first - Mean, 4);
            entropy -= ((float)Histogram[i].second / TotalPacketCount) * log2((float)Histogram[i].second / TotalPacketCount);
            if (Histogram[i].second > ModeCount){
                res->TS_MODE = Histogram[i].first;
                ModeCount = Histogram[i].second;
            }
        }
    }
    res->TS_MEDIAN = Histogram[i - 1].first;
    for (; sum <= 3 * (TotalPacketCount) / 4 && i < (int)Histogram.size(); i++)
    {
        if (Histogram[i].second != 0){
            sum += Histogram[i].second;
            var += Histogram[i].second * std::pow(Histogram[i].first - Mean, 2);
            avg_disp += Histogram[i].second * std::abs(Histogram[i].first - Mean);
            rms += Histogram[i].second * (Histogram[i].first * Histogram[i].first);
            fisher_3 += ((float)Histogram[i].second / TotalPacketCount) * pow(Histogram[i].first, 3);
            kurtosis += Histogram[i].second * pow(Histogram[i].first - Mean, 4);
            entropy -= ((float)Histogram[i].second / TotalPacketCount) * log2((float)Histogram[i].second / TotalPacketCount);
            if (Histogram[i].second > ModeCount){
                res->TS_MODE = Histogram[i].first;
                ModeCount = Histogram[i].second;
            }
        }
    }
    res->TS_Q3 = Histogram[i - 1].first;
    for (; i < (int)Histogram.size(); i++)
    {
        if (Histogram[i].second != 0){
            sum += Histogram[i].second;
            var += Histogram[i].second * std::pow(Histogram[i].first - Mean, 2);
            avg_disp += Histogram[i].second * std::abs(Histogram[i].first - Mean);
            rms += Histogram[i].second * (Histogram[i].first * Histogram[i].first);
            fisher_3 += ((float)Histogram[i].second / TotalPacketCount) * pow(Histogram[i].first, 3);
            kurtosis += Histogram[i].second * pow(Histogram[i].first - Mean, 4);
            entropy -= ((float)Histogram[i].second / TotalPacketCount) * log2((float)Histogram[i].second / TotalPacketCount);
            if (Histogram[i].second > ModeCount){
                res->TS_MODE = i;
                ModeCount = Histogram[i].second;
            }
        }
    }

    //if (sum != TotalPacketCount){
    //    std::cerr << "ERROR sum: "<< sum <<"!="<< TotalPacketCount << " TotalPacketCount"<<std::endl;
    //}

    res->TS_MIN = Histogram[0].first;
    res->TS_MAX = Histogram[Histogram.size() - 1].first;
    res->TS_VAR = var / TotalPacketCount;
    res->TS_STDEV = sqrt(var / TotalPacketCount);

    if (res->TS_MEAN + res->TS_STDEV != 0)
        res->TS_BURSTINESS = (res->TS_STDEV - res->TS_MEAN) / (res->TS_STDEV + res->TS_MEAN);

    if (res->TS_MEAN != 0){
        res->TS_COEFFICIENT_OF_VARIATION = res->TS_STDEV / Mean * 100;
        res->TS_PERCENT_DEVIATION = res->TS_AVERAGE_DISPERSION / Mean * 100;
    }
    res->TS_AVERAGE_DISPERSION = avg_disp / TotalPacketCount;
    
    res->TS_ROOT_MEAN_SQUARE = sqrt(rms / TotalPacketCount);

    double f3;
    double f2 = std::modf(Mean, &f3);
    f2 = abs(f2);

    sum = 0;
    if (f2 <= 0.1){
        f3--;
    }

    for (i = 0; i < (int)Histogram.size() && Histogram[i].first <= (uint16_t)f3; i++){
        sum += Histogram[i].second;
    }

    res->TS_PERCENT_BELOW_MEAN = (float)sum / TotalPacketCount;
    
    if (f2 < 0.1 && i < (int)Histogram.size()){
        sum += Histogram[i].second;
    }

    res->TS_PERCENT_ABOVE_MEAN = (float)(TotalPacketCount - sum) / TotalPacketCount;

    // SKEWNESS
    if (res->TS_STDEV != 0)
    {
        res->TS_PEARSON_SK1_SKEWNESS = (Mean - res->TS_MODE) / res->TS_STDEV;
        res->TS_PEARSON_SK2_SKEWNESS = (3 * Mean - res->TS_MEDIAN) / res->TS_STDEV;
        res->TS_FISHER_MI_3_SKEWNESS = (fisher_3 - (3 * Mean * res->TS_VAR) - pow(Mean, 3)) / pow(res->TS_STDEV, 3);
    }
    if ((res->TS_Q3 != res->TS_Q1))
        res->TS_GALTON_SKEWNESS = (float)(res->TS_Q1 + res->TS_Q3 - 2 * res->TS_MEDIAN) / (res->TS_Q3 - res->TS_Q1);

    if (pow(res->TS_VAR, 2) != 0)
        res->TS_KURTOSIS = kurtosis / (TotalPacketCount * pow(res->TS_VAR, 2));

    res->TS_ENTROPY = entropy;

    if (TotalPacketCount != 1)
        res->TS_SCALED_ENTROPY = res->TS_ENTROPY / log2(TotalPacketCount);

    std::pair<uint16_t, uint16_t> MinHeap[10];
    uint8_t MinHeapSize = 1;
    for (uint16_t i = 0; i < Histogram.size(); i++){
        if (Histogram[i].first != 0){
            if (MinHeapSize < 10){
                MinHeap[MinHeapSize] = Histogram[i];

                for (uint8_t j = MinHeapSize; j > 1; j /= 2){ // buble up
                    if (MinHeap[j / 2].second > MinHeap[j].second){
                        auto tmp = MinHeap[j / 2];
                        MinHeap[j / 2] = MinHeap[j];
                        MinHeap[j] = tmp;
                    }
                    else{
                        break;
                    }
                }
                MinHeapSize++;
            }
            else if (MinHeap[1].second < Histogram[i].second){
                MinHeap[1] = Histogram[i];
                uint8_t j = 1;
                while (j < MinHeapSize){
                    if (j * 2 + 1 < MinHeapSize){
                        uint16_t min = MinHeap[j * 2].second;

                        if (MinHeap[j * 2 + 1].second < min)
                            min = MinHeap[j * 2 + 1].second;

                        if (min >= MinHeap[j].second)
                            break;

                        if (min == MinHeap[j * 2].second){
                            auto tmp = MinHeap[j * 2];
                            MinHeap[j * 2] = MinHeap[j];
                            MinHeap[j] = tmp;
                            j *= 2;
                            continue;
                        }
                        else{
                            auto tmp = MinHeap[j * 2 + 1];
                            MinHeap[j * 2 + 1] = MinHeap[j];
                            MinHeap[j] = tmp;
                            j *= 2;
                            j++;
                            continue;
                        }
                    }
                    else if (j * 2 < MinHeapSize){
                        if (MinHeap[j * 2].second < MinHeap[j].second){
                            auto tmp = MinHeap[j * 2];
                            MinHeap[j * 2] = MinHeap[j];
                            MinHeap[j] = tmp;
                            j *= 2;
                            j++;
                            continue;
                        }
                    }
                    break;
                }
            }
        }
    }

    for (int i = 1; i < MinHeapSize; i++){
        if(MinHeap[i].first != 0 && ((1 / (float)MinHeap[i].first) - (float)MinHeap[i].second / TotalPacketCount != -1 ) )
            res->TS_P_BENFORD += abs(log10(1 + 1 / (float)MinHeap[i].first) - (float)MinHeap[i].second / TotalPacketCount);
    }
    res->TS_P_BENFORD = 1 - res->TS_P_BENFORD / 2;

    return res;
}

TS_behavior_result *RecordExtTIMESERIES::calculatePeriodicity(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value, const std::vector<std::pair<uint16_t, uint16_t>> &Histogram)
{
    const float THRESHOLD = 0.95f;
    const int NUMBER_THRESHOLD = 3;

    TS_behavior_result *Res = new TS_behavior_result;
    if (value.size() < NUMBER_THRESHOLD)
        return Res;

    float probability_sum = 0;
    int val = 0;
    for (size_t i = 0; i < Histogram.size(); i++)
    {
        float probability = (float)Histogram[i].second / value.size();
        if (probability >= THRESHOLD)
        {
            val = Histogram[i].first;
            break;
        }
        probability_sum += probability;
        if (1 - probability_sum < THRESHOLD)
        {
            return Res;
        }
    }
    if (val == 0)
        return Res;

    int64_t last_seen = -1;
    std::map<int64_t, uint16_t> DiffTimes;
    for (size_t i = 0; i < value.size(); i++)
    {
        if (val == value[i])
        {
            if (last_seen == -1)
            {
                last_seen = time[i] / 10;
            }
            else
            {
                int64_t tmp = time[i] / 10 - last_seen;
                DiffTimes[tmp]++;
                last_seen = time[i] / 10;
            }
        }
    }
    int64_t per_time = -1;
    uint16_t per_time_counts = 0;
    for (auto it = DiffTimes.begin(); it != DiffTimes.end(); it++)
    {
        if (per_time == -1)
        {
            per_time = it->first;
            per_time_counts = it->second;
        }
        else
        {
            if (per_time_counts < it->second)
            {
                per_time = it->first;
                per_time_counts = it->second;
            }
        }
    }
    if (per_time_counts > 1)
    {
        Res->TS_PERIODICITY_VAL = val;
        Res->TS_PERIODICITY_TIME = per_time * 10;
    }
    return Res;
}

TS_behavior_result *RecordExtTIMESERIES::calculateBehavior(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value, const std::vector<std::pair<uint16_t, uint16_t>> &Histogram)
{
    TS_behavior_result *Result = calculatePeriodicity(time, value, Histogram);
    Result->TS_HURST_EXPONENT = calculateHurstExponent(value); // CalculateHurstExponent(time,value);
    if (time.size() < 2)
        return Result;
    Result->TS_DIRECTIONS = (float)Directions / time.size();                                
    Result->TS_SWITCHING_METRIC = Switching / (( (float) time.size() - 1) /2);                           
    return Result;
}

TS_frequency_result *RecordExtTIMESERIES::calculateFrequency(const std::vector<uint32_t> &time, const std::vector<uint16_t> &value)
    {
    TS_frequency_result *Result = new TS_frequency_result;

    const double oversampling_factor = NFFT_OVERSAMPLING_FACTOR;
    const double highest_freq_factor = NFFT_HIGHEST_FREQ_FACTOR;

    if (value.size() < 3 || value.size() < MIN_PACKETS_NFFT ){
        return Result;
    }
    if (time[time.size() - 1] == 0){
        return Result;
    }

    LS *LombScargle = computePeriodogram(time, value, oversampling_factor, highest_freq_factor);
    if (LombScargle->nfreqs <= 1){
        delete (LombScargle);
        return Result;
    }



    uint32_t MinIndex = 0, MaxIndex = 0;
    Result->TS_MIN_POWER = LombScargle->Pn[0];
    Result->TS_MAX_POWER = LombScargle->Pn[0];
    for (int i = 0; i < LombScargle->nfreqs; i++){
        if(std::isnan(LombScargle->Pn[i]))
            LombScargle->Pn[i] =0;

        if(std::isnan(LombScargle->freqs[i]))
            LombScargle->freqs[i] =0;


        Result->TS_SPECTRAL_ENERGY += LombScargle->Pn[i];
        if(LombScargle->Pn[i] != 0)
            Result->TS_SPECTRAL_ENTROPY -= LombScargle->Pn[i] * log2(LombScargle->Pn[i]);
        Result->TS_SPECTRAL_CENTROID += LombScargle->Pn[i] * LombScargle->freqs[i];

        if (LombScargle->Pn[i] > Result->TS_MAX_POWER){
            Result->TS_MAX_POWER = LombScargle->Pn[i];
            MaxIndex = i;
            continue;
        }
        if (LombScargle->Pn[i] < Result->TS_MIN_POWER){
            Result->TS_MIN_POWER = LombScargle->Pn[i];
            MinIndex = i;
        }
    }


    Result->TS_MAX_POWER_FREQ = LombScargle->freqs[MaxIndex];
    Result->TS_MIN_POWER_FREQ = LombScargle->freqs[MinIndex];

    Result->TS_SPECTRAL_CENTROID /= Result->TS_SPECTRAL_ENERGY;
    double Mean = Result->TS_SPECTRAL_ENERGY / LombScargle->nfreqs;
    Result->TS_POWER_MEAN = Mean;
    double var = 0;
    double kurtosis = 0;

    Result->TS_SPECTRAL_CREST = Result->TS_MAX_POWER / Mean;

    for (int i = 0; i < LombScargle->nfreqs; i++){
        Result->TS_SPECTRAL_KURTOSIS += pow((LombScargle->Pn[i] - Mean), 4);
        var += pow((LombScargle->Pn[i] - Mean), 2);
        kurtosis += pow((LombScargle->Pn[i] - Mean), 4);
        Result->TS_SPECTRAL_SPREAD += pow(LombScargle->freqs[i] - Result->TS_SPECTRAL_CENTROID, 2) * LombScargle->Pn[i];
        Result->TS_SPECTRAL_BANDWIDTH +=  LombScargle->Pn[i] * sqrt(LombScargle->freqs[i]-Result->TS_SPECTRAL_CENTROID);
    }

    Result->TS_SPECTRAL_SPREAD /= Result->TS_SPECTRAL_ENERGY;
    Result->TS_SPECTRAL_SPREAD = sqrt(Result->TS_SPECTRAL_SPREAD);
    var /= LombScargle->nfreqs;

    Result->TS_POWER_STD = sqrt(var);
    kurtosis /= LombScargle->nfreqs;
    kurtosis /= var * var;

    Result->TS_SPECTRAL_KURTOSIS /= LombScargle->nfreqs * var * var;

    for (int i = 0; i < LombScargle->nfreqs - 1; i++){
        Result->TS_SPECTRAL_FLUX += std::abs(LombScargle->Pn[i] - LombScargle->Pn[i + 1]);
    }

    for (int i = 0; i < LombScargle->nfreqs; i++){
        Result->TS_SPECTRAL_ROLLOFF += LombScargle->Pn[i];
        if (Result->TS_SPECTRAL_ROLLOFF >= 0.85 * Result->TS_SPECTRAL_ENERGY){
            Result->TS_SPECTRAL_ROLLOFF = LombScargle->freqs[i];
            break;
        }
    }

    Result->TS_SPECTRAL_SLOPE = LogPolyFit1D(LombScargle->freqs, LombScargle->Pn, (size_t)LombScargle->nfreqs);

    Result->TS_PERIODICITY_SCDF = 1 - exp(-(Result->TS_MAX_POWER * 0.1) / var);

    if (Result->TS_POWER_STD != 0){
        std::nth_element(LombScargle->Pn, LombScargle->Pn + (LombScargle->nfreqs / 2) + 1, LombScargle->Pn + (size_t)LombScargle->nfreqs);
        Result->TS_SPECTRAL_SKEWNESS = (3 * Mean - LombScargle->Pn[LombScargle->nfreqs / 2]) / Result->TS_POWER_STD; // PEARSON_SK2_SKEWNESS
    }

    delete LombScargle;
    return Result;
    }



__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("timeseries", [](){return new TIMESERIESPlugin();});
   register_plugin(&rec);
   RecordExtTIMESERIES::REGISTERED_ID = register_extension();
}
                                    //Default values
TIMESERIESPlugin::TIMESERIESPlugin():Statistics(true),Time(false),Behavior(false),Frequency(false)
{                                   

}

TIMESERIESPlugin::~TIMESERIESPlugin()
{
}

void TIMESERIESPlugin::init(const char *params)
{

   TIMESERIESParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }
   if(!parser.useDefault()){
        Statistics =parser.Statistics;
        Time =parser.Time;
        Behavior = parser.Behavior;
        Frequency = parser.Frequency;
   }

}

void TIMESERIESPlugin::close()
{
}

ProcessPlugin *TIMESERIESPlugin::copy()
{
   return new TIMESERIESPlugin(*this);
}



int TIMESERIESPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtTIMESERIES * r = new RecordExtTIMESERIES(Statistics,Time,Behavior,Frequency);

   rec.add_extension(r);

    if(r->SizeData != nullptr)
        r->SizeData->add(pkt.payload_len%1501);
    if (r->TimeData !=nullptr)
        r->TimeData->Add((rec.time_first.tv_sec - pkt.ts.tv_sec)*1000000 + (rec.time_first.tv_usec-pkt.ts.tv_usec));
   
   return 0;
}

int TIMESERIESPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtTIMESERIES *r = (RecordExtTIMESERIES *) rec.get_extension(RecordExtTIMESERIES::REGISTERED_ID);
    if(r == nullptr){
        return 0;
    }
    if(r->Full){
        if(TS_FLUSH_WHEN_FULL){
            return FLOW_FLUSH;
        }
        return 0;
    }
        
    
    if(r->SizeData != nullptr)
        r->Full |= r->SizeData->add(pkt.payload_len%1501);

    if (r->TimeData !=nullptr)
        r->Full |= r->TimeData->Add((rec.time_first.tv_sec - pkt.ts.tv_sec)*1000000 + (rec.time_first.tv_usec-pkt.ts.tv_usec));
    


   if(Behavior){
    bool packetDirection=false;
    if(rec.ip_version == 4){
        packetDirection = (rec.src_ip.v4 == pkt.src_ip.v4);
    }else{
        packetDirection = (rec.src_ip.v6 == pkt.src_ip.v6);
    }
    if(packetDirection)
        r->Directions++;

    if(packetDirection != r->LastDirection){
        r->Switching++;
        r->LastDirection = !r->LastDirection;
    }
        

   }
   return 0;
}


void TIMESERIESPlugin::pre_export(Flow &rec)
{
RecordExtTIMESERIES *r = (RecordExtTIMESERIES *) rec.get_extension(RecordExtTIMESERIES::REGISTERED_ID);
    if(r == nullptr){
        return;
    }
    r->calculateResult();
}

}
