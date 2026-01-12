#pragma once

#include <chrono>
#include <random>
#include <thread>

void randomWait() noexcept
{
	static thread_local std::mt19937 gen(std::random_device {}());
	std::uniform_int_distribution<> dist(0, 10);
	const int delay = dist(gen);
	std::this_thread::sleep_for(std::chrono::microseconds(delay));
}