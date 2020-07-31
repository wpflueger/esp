#include "eu_black_scholes.hpp"

#include <iostream>

int main(int argc, char **argv) {
    // First we create the parameter list
    fpdata_t S = 100.0;  // Option price
    fpdata_t K = 100.0;  // Strike price
    fpdata_t r = 0.05;   // Risk-free rate (5%)
    fpdata_t v = 0.2;    // Volatility of the underlying (20%)
    fpdata_t T = 1.0;    // One year until expiry

    // Then we calculate the call/put values
    fpdata_t call = call_price(S, K, r, v, T);
    fpdata_t put = put_price(S, K, r, v, T);

    // Finally we output the parameters and prices
    std::cout << "INFO: Underlying:      " << S << std::endl;
    std::cout << "INFO: Strike:          " << K << std::endl;
    std::cout << "INFO: Risk-Free Rate:  " << r << std::endl;
    std::cout << "INFO: Volatility:      " << v << std::endl;
    std::cout << "INFO: Maturity:        " << T << std::endl;

    std::cout << "INFO: Call Price:      " << call << std::endl;
    std::cout << "INFO: Put Price:       " << put << std::endl;

    return 0;
}
