#include <chrono>
#include <iostream>

class TimeLog {
private:
    std::chrono::high_resolution_clock::time_point start;

public:
    TimeLog() {
        start = std::chrono::high_resolution_clock::now();
    }

    ~TimeLog() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        auto seconds = duration / 1E6;
        std::cout << "Time elapsed: " << seconds << " seconds\n";
    }
};
