#ifndef __EU_BLACK_SCHOLES__
#define __EU_BLACK_SCHOLES__

#include <ac_float.h>

#define fpdata_t ac_private::ac_float_cdouble_t

// Standard normal probability density function
fpdata_t norm_pdf(const fpdata_t& x);

// An approximation to the cumulative distribution function
// for the standard normal distribution
// Note: This is a recursive function
fpdata_t norm_cdf(const fpdata_t& x);

// This calculates d_j, for j in {1,2}. This term appears in the closed
// form solution for the European call or put price
fpdata_t d_j(const int& j, const fpdata_t& S, const fpdata_t& K, const fpdata_t& r, const fpdata_t& v, const fpdata_t& T);

// Calculate the European vanilla call price based on
// underlying S, strike K, risk-free rate r, volatility of
// underlying sigma and time to maturity T
fpdata_t call_price(const fpdata_t& S, const fpdata_t& K, const fpdata_t& r, const fpdata_t& v, const fpdata_t& T);

// Calculate the European vanilla put price based on
// underlying S, strike K, risk-free rate r, volatility of
// underlying sigma and time to maturity T
fpdata_t put_price(const fpdata_t& S, const fpdata_t& K, const fpdata_t& r, const fpdata_t& v, const fpdata_t& T);

#endif
