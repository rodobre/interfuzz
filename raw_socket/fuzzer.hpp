#pragma once

/// Libraries from the C++ standard
#include <functional>
#include <utility>
#include <type_traits>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>

#include <cmath>

/// Linux thread & process libraries
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/time.h>

/// Pretty print library
#include "pretty_print.hpp"

template <typename T>
using fn_callback_T = std::function<void(std::shared_ptr<T>&, size_t, uint32_t, double)>;

template <typename T>
void DriverFuzzer(
    std::mutex&             mtx,
    std::shared_ptr<T>&     ptr,
    fn_callback_T<T>        fn, 
    size_t                  sz,
    uint32_t                thread_id,
    double                  freq
    )
{
    mtx.lock();
    mtx.unlock();

    fn(ptr, sz, thread_id, freq);
}

template <typename T>
class Fuzzer
{
    private:
        std::shared_ptr<T> ptr;
        size_t obj_size;
        fn_callback_T<T> fn_callback;
        double frequency;

    public:

        Fuzzer()
        :
            ptr(),
            obj_size(0u),
            fn_callback(),
            frequency(0.0)
        {    
        }

        Fuzzer(std::shared_ptr<T>& _ptr, fn_callback_T<T> _fn_callback,
                 size_t _obj_size, double _frequency = 1.0)
        :
            ptr(_ptr),
            fn_callback(_fn_callback),
            obj_size(_obj_size),
            frequency(_frequency)
        {
            if(frequency == 0.0)
                frequency = 0.0001;
        }

        ~Fuzzer()
        {
        }

        Fuzzer(Fuzzer const&)           = delete;
        void operator=(Fuzzer const&)   = delete;

        void SetPtr(const std::shared_ptr<T>& _ptr)
        {
            ptr = _ptr;
        }

        void SetFreq(double freq)
        {
            if(freq == 0.0)
                frequency = 0.0001;
            frequency = freq;
        }

        void StartFuzzing()
        {
            PrettyPrint::PrintInfo("Preparing fuzzer...");
            PrettyPrint::PrintDebug("Fuzzing on pointer type \"%s\" with frequency %0.6f.",
                                        typeid(T).name(), frequency);
            
            auto pid            = getpid();
            uint32_t thread_ctr = std::thread::hardware_concurrency();
            PrettyPrint::PrintWarning("This operation will use [%u] threads at maximum capacity.", thread_ctr);
            PrettyPrint::PrintInfo("Preparing the delayed thread pool start...");

            std::mutex thread_launcher;
            thread_launcher.lock();

            cpu_set_t cpuset;

            auto prev_priority  = getpriority(PRIO_PROCESS, pid);
            auto result         = setpriority(PRIO_PROCESS, pid, -20);
            auto cur_priroity   = getpriority(PRIO_PROCESS, pid);

            if(result != 0)
            {
                PrettyPrint::PrintError("Cannot assign lowest niceness for the current process... Error: [%d]\n", result);
                return;
            }

            PrettyPrint::PrintInfo("Changed scheduling niceness from [%d] to [%d] for current process.",
                                prev_priority, cur_priroity);
            
            std::vector<std::thread> threads(thread_ctr);
            for(uint32_t i = 0u; i < thread_ctr; ++i)
            {
                threads[i] = std::thread(DriverFuzzer<T>, std::ref(thread_launcher), std::ref(ptr),
                                            fn_callback, obj_size, i, frequency);

                pthread_t thread_handle = threads[i].native_handle();

                struct sched_param thread_param;
                auto default_policy = sched_getscheduler(pid);
                thread_param.__sched_priority = sched_get_priority_max(default_policy);
                pthread_setschedparam(thread_handle, default_policy, &thread_param);

                PrettyPrint::PrintInfo("Set thread ID [%u] real time [policy: %d] priority to [%u]",
                                i, default_policy, thread_param.__sched_priority);

                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);

                auto result = pthread_setaffinity_np(thread_handle, sizeof(cpu_set_t), &cpuset);
                if(result != 0)
                {
                    PrettyPrint::PrintError("Cannot set affinity for thread ID [%u] to CPU [%u]", i, i);
                    break;
                }

                PrettyPrint::PrintInfo("Assigned thread ID [%u] to CPU core [%u]", i, i);
            }

            PrettyPrint::PrintInfo("Threads initialized, starting in 3 seconds...");
            std::this_thread::sleep_for(std::chrono::seconds(3u));

            auto start = std::chrono::system_clock::now();
            thread_launcher.unlock();

            for(auto& thread : threads)
                thread.join();

            auto end = std::chrono::system_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            PrettyPrint::PrintInfo("Fuzzing operation completed in [%d ms].", duration.count());
        }
};