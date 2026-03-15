#include "dummyReader.hpp"
#include "dummyWriter.hpp"

#include <chrono>
#include <future>
#include <latch>
#include <numeric>
#include <vector>

#include <gtest/gtest.h>
#include <outputStorage/b2OutputStorage.hpp>
#include <outputStorage/bOutputStorage.hpp>
#include <outputStorage/ffq2OutputStorage.hpp>
#include <outputStorage/ffqOutputStorage.hpp>
#include <outputStorage/lfnbOutputStorage.hpp>
#include <outputStorage/mc2OutputStorage.hpp>
#include <outputStorage/mcOutputStorage.hpp>
#include <outputStorage/mq2OutputStorage.hpp>
#include <outputStorage/mqOutputStorage.hpp>
#include <outputStorage/ringOutputStorage.hpp>
#include <outputStorage/threadAffinitySetter.hpp>
// #include <outputStorage/serializedOutputStorage.hpp>
// #include <outputStorage/serializedOutputStorageBlocking.hpp>
#include <outputStorage/outputStorageRegistrar.hpp>

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
	ipxp::output::OutputStorageRegistrar<OutputStorageType> storageRegistrar(writersCount);

	if (std::ranges::any_of(readerGroupSizes, [&](const auto readerCount) {
			return readerCount == 0;
		})) {
		throw std::invalid_argument("Reader count in group cannot be zero");
	}

	std::vector<ipxp::output::OutputStorageReaderGroup<void*>*> readerGroups;
	for (const std::size_t readerGroupSize : readerGroupSizes) {
		readerGroups.emplace_back(&storageRegistrar.registerReaderGroup(readerGroupSize));
	}

	boost::container::static_vector<boost::container::static_vector<DummyReader, 32>, 8> readers;
	for (std::size_t i = 0; i < readerGroups.size(); i++) {
		const uint8_t readerGroupSize = readerGroupSizes[i];
		readers.emplace_back(
			boost::container::static_vector<DummyReader, 32>(
				readerGroupSize,
				DummyReader(*readerGroups[i], immitateWork)));
	}

	std::vector<DummyWriter<OutputStorageType>> writers(
		writersCount,
		DummyWriter<OutputStorageType>(containersToWritePerWriter, storageRegistrar, immitateWork));
	std::latch readersLatch(totalReaders);
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	std::vector<std::vector<std::future<std::size_t>>> readContainers;
	for (auto& readerGroup : readers) {
		readContainers.emplace_back();
		for (DummyReader& reader : readerGroup) {
			readContainers.back().emplace_back(
				std::async(std::launch::async, [&reader, &readersLatch]() {
					ipxp::output::ThreadAffinitySetter::setNumaNode(0);
					readersLatch.count_down();
					return reader.readContainers();
				}));
		}
	}

	readersLatch.wait();
	std::vector<std::future<void>> writerFutures
		= writers | std::views::transform([&](DummyWriter<OutputStorageType>& writer) {
			  return std::async(std::launch::async, [&]() {
				  ipxp::output::ThreadAffinitySetter::setNumaNode(0);
				  writer.writeContainers();
			  });
		  })
		| std::ranges::to<std::vector<std::future<void>>>();

	std::ranges::for_each(writerFutures, [](std::future<void>& future) { future.get(); });

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

/*template<typename OutputStorageType>
void stressTest(const bool immitateWork)
{
	std::cout << "Stress Test: X Writers, X Group X Readers"
			  << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(32, {32}, immitateWork, 100'096);
}

template<typename OutputStorageType>
void shortTestLoop(const bool immitateWork)
{
	for (const auto testIndex : std::views::iota(0, 100)) {
		std::cout << " Short Test Loop Iteration " << testIndex << "\n";
		makeTest<OutputStorageType>(32, {1}, immitateWork, 1000);
	}
}
*/

template<typename OutputStorageType>
void makePerformanceTest(std::string_view storageName)
{
	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 1 Writers, 1 Reader\n";
	makeTest<OutputStorageType>(1, {1}, false, 80'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 32 Writers, 1 Reader\n";
	makeTest<OutputStorageType>(32, {1}, false, 20'000'064);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 1 Writers, 32 Readers\n";
	makeTest<OutputStorageType>(1, {32}, false, 70'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 32 Writers, 32 Readers\n";
	makeTest<OutputStorageType>(32, {32}, false, 20'000'064);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 4 Writers, 4 Group 1 Reader\n";
	makeTest<OutputStorageType>(4, {1, 1, 1, 1}, false, 80'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << storageName << ", 32 Writers, 4 Group 8 Reader\n";
	makeTest<OutputStorageType>(32, {8, 8, 8, 8}, false, 20'000'000);
}

TEST(TestOutputStorage, XXX)
{
	ipxp::output::ThreadAffinitySetter::setNumaNode(0);
	std::cout << "==========================================================" << std::endl;
	std::cout << "MQ2OutputStorage, 1 Writers, 1 Reader\n";
	makeTest<ipxp::output::MQ2OutputStorage<void*>>(1, {1}, false, 80'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQ2OutputStorage, 32 Writers, 1 Reader\n";
	makeTest<ipxp::output::MQ2OutputStorage<void*>>(32, {1}, false, 20'000'064);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQ2OutputStorage, 32 Writers, 32 Readers\n";
	makeTest<ipxp::output::MQ2OutputStorage<void*>>(32, {32}, false, 20'000'064);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQ2OutputStorage, 4 Writers, 4 Group 1 Reader\n";
	makeTest<ipxp::output::MQ2OutputStorage<void*>>(4, {1, 1, 1, 1}, false, 80'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQ2OutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::MQ2OutputStorage<void*>>(32, {8, 8, 8, 8}, false, 20'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQOutputStorage, 1 Writers, 1 Reader\n";
	makeTest<ipxp::output::MQOutputStorage<void*>>(1, {1}, false, 80'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQOutputStorage, 32 Writers, 1 Reader\n";
	makeTest<ipxp::output::MQOutputStorage<void*>>(32, {1}, false, 20'000'064);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQOutputStorage, 32 Writers, 32 Readers\n";
	makeTest<ipxp::output::MQOutputStorage<void*>>(32, {32}, false, 20'000'064);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQOutputStorage, 4 Writers, 4 Group 1 Reader\n";
	makeTest<ipxp::output::MQOutputStorage<void*>>(4, {1, 1, 1, 1}, false, 80'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQOutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::MQOutputStorage<void*>>(32, {8, 8, 8, 8}, false, 20'000'000);
	makePerformanceTest<ipxp::output::MCOutputStorage<void*>>("MCOutputStorage");
	makePerformanceTest<ipxp::output::LFNBOutputStorage<void*>>("LFNBOutputStorage");

	makePerformanceTest<ipxp::output::MC2OutputStorage<void*>>("MC2OutputStorage");
	makePerformanceTest<ipxp::output::B2OutputStorage<void*>>("B2OutputStorage");
	makePerformanceTest<ipxp::output::BOutputStorage<void*>>("BOutputStorage");
	makePerformanceTest<ipxp::output::FFQ2OutputStorage<void*>>("FFQ2OutputStorage");
	makePerformanceTest<ipxp::output::FFQOutputStorage<void*>>("FFQOutputStorage");

	std::cout << "Ring, 1 Writers, 1 Reader\n";
	makeTest<ipxp::output::RingOutputStorage<void*>>(1, {1}, false, 30'000'000);
	std::cout << "Ring, 32 Writers, 1 Reader\n";

	makeTest<ipxp::output::RingOutputStorage<void*>>(32, {1}, false);
	std::cout << std::endl;
}

TEST(TestOutputStorage, YYY)
{
	makeTest<ipxp::output::RingOutputStorage<void*>>(32, {1}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "B2OutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::B2OutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "BOutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::BOutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "FFQ2OutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::FFQ2OutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "FFQOutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::FFQOutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQOutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::MQOutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MCOutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::MCOutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MC2OutputStorage, 32 Writers, ...\n";
	makeTest<ipxp::output::MC2OutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "LFNBOutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::LFNBOutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);

	std::cout << "==========================================================" << std::endl;
	std::cout << "MQ2OutputStorage, 32 Writers, 4 Group 8 Reader\n";
	makeTest<ipxp::output::MQ2OutputStorage<void*>>(32, {8, 8, 8, 8}, false, 2'000'000);
}

TEST(TestOutputStorage, Debug)
{
	ipxp::output::ThreadAffinitySetter::setNumaNode(0);
	makePerformanceTest<ipxp::output::B2OutputStorage<void*>>("B2OutputStorage");
	return;
	for (const auto testIndex : std::views::iota(0, 100)) {
		std::cout << " Debug Loop Iteration " << testIndex << "\n";
		makeTest<ipxp::output::BOutputStorage<void*>>(32, {32}, false, 10'000'000);
	}
}

TEST(TestOutputStorage, Perf)
{
	std::cout << "Perf test" << std::endl;
	// makePerformanceTest<ipxp::output::MCOutputStorage>("MCOutputStorage");
	makeTest<ipxp::output::RingOutputStorage<void*>>(1, {1}, false, 10'000'064);
}
