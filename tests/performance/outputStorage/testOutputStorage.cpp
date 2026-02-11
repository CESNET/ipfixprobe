#include "dummyReader.hpp"
#include "dummyWriter.hpp"

#include <chrono>
#include <future>
#include <latch>
#include <numeric>
#include <vector>

#include <gtest/gtest.h>
#include <outputStorage/bOutputStorage.hpp>
#include <outputStorage/ffqOutputStorage.hpp>
#include <outputStorage/lfnbOutputStorage.hpp>
#include <outputStorage/mcOutputStorage.hpp>
#include <outputStorage/mqOutputStorage.hpp>
#include <outputStorage/ringOutputStorage.hpp>
#include <outputStorage/serializedOutputStorage.hpp>
#include <outputStorage/serializedOutputStorageBlocking.hpp>

template<typename OutputStorageType>
void makeTest(
	const std::size_t writersCount,
	const std::vector<std::size_t> readerGroupSizes,
	const bool immitateWork,
	const std::size_t containersToWritePerWriter = 1'000'064)
{
	const std::size_t totalReaders = std::accumulate(
		readerGroupSizes.begin(),
		readerGroupSizes.end(),
		0ULL,
		std::plus<std::size_t>());
	OutputStorageType storage(writersCount);

	if (std::ranges::any_of(readerGroupSizes, [&](const auto readerCount) {
			return readerCount == 0;
		})) {
		throw std::invalid_argument("Reader count in group cannot be zero");
	}

	auto readers = readerGroupSizes | std::views::transform([&](const std::size_t readerGroupSize) {
					   ipxp::output::OutputStorage::ReaderGroupHandler& readerGroupHandler
						   = storage.registerReaderGroup(readerGroupSize);
					   return std::vector<DummyReader>(
						   readerGroupSize,
						   DummyReader(storage, readerGroupHandler, immitateWork));
				   })
		| std::ranges::to<std::vector<std::vector<DummyReader>>>();

	std::vector<DummyWriter> writers(
		writersCount,
		DummyWriter(containersToWritePerWriter, storage, immitateWork));
	std::latch readersLatch(totalReaders);
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	std::vector<std::vector<std::future<std::size_t>>> readContainers;
	for (std::vector<DummyReader>& readerGroup : readers) {
		readContainers.emplace_back();
		for (DummyReader& reader : readerGroup) {
			readContainers.back().emplace_back(
				std::async(std::launch::async, [&reader, &readersLatch]() {
					readersLatch.count_down();
					return reader.readContainers();
				}));
		}
	}

	readersLatch.wait();
	std::vector<std::future<void>> writerFutures
		= writers | std::views::transform([&](DummyWriter& writer) {
			  return std::async(std::launch::async, [&]() { writer.writeContainers(); });
		  })
		| std::ranges::to<std::vector<std::future<void>>>();

	std::ranges::for_each(writerFutures, [](std::future<void>& future) { future.get(); });
	// writers.clear();

	const std::vector<std::size_t> containersReadInGroups
		= readContainers
		| std::views::transform([](std::vector<std::future<std::size_t>>& groupFutures) {
			  return std::accumulate(
				  groupFutures.begin(),
				  groupFutures.end(),
				  0ULL,
				  [](const std::size_t acc, std::future<std::size_t>& fut) {
					  return acc + fut.get();
				  });
		  })
		| std::ranges::to<std::vector<std::size_t>>();

	const std::size_t totalWrittenContainers = writersCount * containersToWritePerWriter;
	const std::size_t testTime = std::chrono::duration_cast<std::chrono::milliseconds>(
									 std::chrono::steady_clock::now() - startTime)
									 .count();
	std::cout << "Total written containers: " << totalWrittenContainers << "\n";
	std::cout << "Total time taken: " << (testTime / 1000.0) << " s\n";
	for (const std::size_t groupReadContainers : containersReadInGroups) {
		std::cout << "Total read containers: " << groupReadContainers << "\n";
		std::cout << "Lost containers: " << (totalWrittenContainers - groupReadContainers) << "\n";
		std::cout << "Lost containers percentage: "
				  << (100.0 * (totalWrittenContainers - groupReadContainers)
					  / totalWrittenContainers)
				  << "%\n";
		std::cout << "Throughput: "
				  << (static_cast<double>(groupReadContainers) / static_cast<double>(testTime))
				  << " Kcontainers/s\n";
	}
}

template<typename OutputStorageType>
void makeTestGroup(const bool immitateWork)
{
	std::cout << "4 Writers, 2 Groups 2 Readers" << (immitateWork ? " With Work" : " No Work")
			  << "\n";
	makeTest<OutputStorageType>(4, {2, 2}, immitateWork);

	std::cout << "1 Writer, 1 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(1, {1}, immitateWork, 10'000'000);

	std::cout << "1 Writer, 32 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(1, {32}, immitateWork, 10'000'000);

	std::cout << "32 Writers, 1 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(32, {1}, immitateWork);

	std::cout << "32 Writers, 1 Group 32 Readers" << (immitateWork ? " With Work" : " No Work")
			  << "\n";
	makeTest<OutputStorageType>(32, {32}, immitateWork);

	std::cout << "4 Writers, 1 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(4, {1}, immitateWork);

	std::cout << "1 Writer, 1 Group 2 Readers" << (immitateWork ? " With Work" : " No Work")
			  << "\n";
	makeTest<OutputStorageType>(1, {2}, immitateWork);
}

template<typename OutputStorageType>
void stressTest(const bool immitateWork)
{
	std::cout << "Stress Test: X Writers, X Group X Readers"
			  << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(4, {1, 1, 1, 1}, immitateWork, 0'200'000);
}

template<typename OutputStorageType>
void shortTestLoop(const bool immitateWork)
{
	for (const auto testIndex : std::views::iota(0, 100)) {
		std::cout << " Short Test Loop Iteration " << testIndex << "\n";
		makeTest<OutputStorageType>(32, {1}, immitateWork, 1000);
	}
}

template<typename OutputStorageType>
void makePerformanceTest(std::string_view storageName)
{
	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 1 Writers, 1 Reader\n";
	makeTest<OutputStorageType>(1, {1}, false, 30'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 32 Writers, 1 Reader\n";
	makeTest<OutputStorageType>(32, {1}, false, 50'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 1 Writers, 32 Readers\n";
	makeTest<OutputStorageType>(1, {32}, false, 70'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 32 Writers, 32 Readers\n";
	makeTest<OutputStorageType>(32, {32}, false, 5'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 4 Writers, 4 Group 1 Reader\n";
	makeTest<OutputStorageType>(4, {1, 1, 1, 1}, false, 30'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 32 Writers, 4 Group 8 Reader\n";
	makeTest<OutputStorageType>(32, {8, 8, 8, 8}, false, 10'000'000);
	std::cout << std::endl;
}

TEST(TestOutputStorage, XXX)
{
	makePerformanceTest<ipxp::output::MCOutputStorage>("MCOutputStorage");
	makePerformanceTest<ipxp::output::BOutputStorage>("BOutputStorage");
	makePerformanceTest<ipxp::output::LFNBOutputStorage>("LFNBOutputStorage");
	makePerformanceTest<ipxp::output::FFQOutputStorage>("FFQOutputStorage");
	makePerformanceTest<ipxp::output::MQOutputStorage>("MQOutputStorage");

	std::cout << "Ring, 1 Writers, 1 Reader\n";
	makeTest<ipxp::output::RingOutputStorage>(1, {1}, false, 30'000'000);
	std::cout << "Ring, 32 Writers, 1 Reader\n";
	makeTest<ipxp::output::RingOutputStorage>(32, {1}, false);
}

TEST(TestOutputStorage, Debug)
{
	for (const auto testIndex : std::views::iota(0, 100)) {
		std::cout << " Debug Loop Iteration " << testIndex << "\n";
		makePerformanceTest<ipxp::output::MCOutputStorage>("MCOutputStorage");
		// stressTest<ipxp::output::MCOutputStorage>(false);
	}
}

TEST(TestOutputStorage, TestB)
{
	std::cout << "1 Writers, 1 Reader\n";
	makeTest<ipxp::output::BOutputStorage>(1, {1}, false);

	std::cout << "32 Writers, 1 Reader\n";
	makeTest<ipxp::output::BOutputStorage>(32, {1}, false);
}

TEST(TestOutputStorage, LFNBTest)
{
	std::cout << "32 Writers, 1 Reader\n";
	makeTest<ipxp::output::LFNBOutputStorage>(32, {1}, false);

	std::cout << "1 Writers, 1 Reader\n";
	makeTest<ipxp::output::LFNBOutputStorage>(1, {1}, false, 100'000'000);
}

TEST(TestOutputStorage, RingTest)
{
	std::cout << "1 Writers, 1 Reader\n";
	makeTest<ipxp::output::RingOutputStorage>(1, {1}, false, 100'000'000);
	std::cout << "32 Writers, 1 Reader\n";
	makeTest<ipxp::output::RingOutputStorage>(32, {1}, false);
}

TEST(TestOutputStorage, SerializationStorageShortTestNoWorkImmitation)
{
	shortTestLoop<ipxp::output::SerializedOutputStorage>(false);
}

TEST(TestOutputStorage, MCStorageTestStressNoWorkImmitation)
{
	makeTestGroup<ipxp::output::MCOutputStorage>(false);
}

TEST(TestOutputStorage, FFQStorageTestStressNoWorkImmitation)
{
	makeTestGroup<ipxp::output::FFQOutputStorage>(false);
}

TEST(TestOutputStorage, LFNBStorageTestStressNoWorkImmitation)
{
	stressTest<ipxp::output::LFNBOutputStorage>(false);
}

TEST(TestOutputStorage, BStorageTestNoWorkImmitation)
{
	makeTestGroup<ipxp::output::BOutputStorage>(false);
}

TEST(TestOutputStorage, LFNBStorageTestNonBlockingNoWorkImmitation)
{
	makeTestGroup<ipxp::output::LFNBOutputStorage>(false);
}

TEST(TestOutputStorage, MQStorageTestNonBlockingNoWorkImmitation)
{
	makeTestGroup<ipxp::output::MQOutputStorage>(false);
}

TEST(TestOutputStorage, SerializationStorageTestNonBlockingNoWorkImmitation)
{
	makeTestGroup<ipxp::output::SerializedOutputStorage>(false);
}

TEST(TestOutputStorage, SerializationStorageTestBlockingNoWorkImmitation)
{
	makeTestGroup<ipxp::output::SerializedOutputStorageBlocking>(false);
}

TEST(TestOutputStorage, SerializationStorageTestNonBlockingWithWorkImmitation)
{
	makeTestGroup<ipxp::output::SerializedOutputStorage>(true);
}

TEST(TestOutputStorage, SerializationStorageTestBlockingWithWorkImmitation)
{
	makeTestGroup<ipxp::output::SerializedOutputStorageBlocking>(true);
}
