//#define _USE_MATH_DEFINES

#include "eu_black_scholes.hpp"

#include <cmath>

//// Standard normal probability density function
//fpdata_t norm_pdf(const fpdata_t& x) {
//    return (1.0/(pow(2*M_PI,0.5)))*exp(-0.5*x*x);
//}

// An approximation to the cumulative distribution function
// for the standard normal distribution
// Note: This is a recursive function
//fpdata_t norm_cdf(const fpdata_t& x) {
//    fpdata_t k = fpdata_t(1.0) / (fpdata_t(1.0) + fpdata_t(fpdata_t(0.2316419) * x));
//    fpdata_t k_sum = k * (fpdata_t(0.319381530) + k * (fpdata_t(-0.356563782) + k * (fpdata_t(1.781477937) + k * (fpdata_t(-1.821255978) + fpdata_t(1.330274429) * k))));
//
//    if (x >= fpdata_t(0.0)) {
//        return (fpdata_t(1.0) - (fpdata_t(1.0) / (pow(fpdata_t(2*M_PI), fpdata_t(0.5)))) * exp(fpdata_t(-0.5) * x * x) * k_sum);
//    } else {
//        return fpdata_t(1.0) - norm_cdf(-x);
//    }
//}
//
//// This calculates d_j, for j in {1,2}. This term appears in the closed
//// form solution for the European call or put price
//fpdata_t d_j(const int& j, const fpdata_t& S, const fpdata_t& K, const fpdata_t& r, const fpdata_t& v, const fpdata_t& T) {
//    return (log(S/K) + (r + (pow(-1,j-1))*0.5*v*v)*T)/(v*(pow(T,0.5)));
//}

// Calculate the European vanilla call price based on
// underlying S, strike K, risk-free rate r, volatility of
// underlying sigma and time to maturity T
fpdata_t call_price(const fpdata_t& S, const fpdata_t& K, const fpdata_t& r, const fpdata_t& v, const fpdata_t& T) {
    //return S * norm_cdf(d_j(1, S, K, r, v, T))-K*exp(-r*T) * norm_cdf(d_j(2, S, K, r, v, T));
    //return 0;
    fpdata_t K_tmp = K;
    return fpdata_t((S * fpdata_t(1.0))) + K_tmp;
}

// Calculate the European vanilla put price based on
// underlying S, strike K, risk-free rate r, volatility of
// underlying sigma and time to maturity T
fpdata_t put_price(const fpdata_t& S, const fpdata_t& K, const fpdata_t& r, const fpdata_t& v, const fpdata_t& T) {
    return 0;
    //return -S*norm_cdf(-d_j(1, S, K, r, v, T))+K*exp(-r*T) * norm_cdf(-d_j(2, S, K, r, v, T));
}
