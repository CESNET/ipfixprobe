#include "dummyReader.hpp"
#include "dummyWriter.hpp"

#include <chrono>
#include <future>
#include <latch>
#include <numeric>
#include <vector>

#include <gtest/gtest.h>
#include <outputStorage/lfnbOutputStorage.hpp>
#include <outputStorage/mqOutputStorage.hpp>
#include <outputStorage/serializedOutputStorage.hpp>
#include <outputStorage/serializedOutputStorageBlocking.hpp>

template<typename OutputStorageType>
void makeTest(
	const std::size_t writersCount,
	const std::vector<std::size_t> readerGroupSizes,
	const bool immitateWork,
	const std::size_t containersToWritePerWriter = 1'000'000)
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
					   const std::size_t readerGroupIndex
						   = storage.registerReaderGroup(readerGroupSize);
					   return std::vector<DummyReader>(
						   readerGroupSize,
						   DummyReader(storage, readerGroupIndex, immitateWork));
				   })
		| std::ranges::to<std::vector<std::vector<DummyReader>>>();

	std::vector<DummyWriter> writers(
		writersCount,
		DummyWriter(containersToWritePerWriter, storage, immitateWork));
	std::latch readersLatch(totalReaders);
	std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
	std::vector<std::vector<std::future<std::size_t>>> readContainers
		= readers | std::views::transform([&](std::vector<DummyReader>& readerGroup) {
			  return readerGroup | std::views::transform([&](DummyReader& reader) {
						 return std::async(std::launch::async, [&]() {
							 readersLatch.count_down();
							 return reader.readContainers();
						 });
					 })
				  | std::ranges::to<std::vector<std::future<std::size_t>>>();
		  })
		| std::ranges::to<std::vector<std::vector<std::future<std::size_t>>>>();

	readersLatch.wait();
	std::vector<std::future<void>> writerFutures = writers
		| std::views::transform([&](DummyWriter& writer) {
													   return std::async(std::launch::async, [&]() {
														   storage.registerWriter();
														   writer.writeContainers();
													   });
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

	const std::size_t totalWrittenContainers = writersCount * 1'000'000;
	std::cout << "Total written containers: " << totalWrittenContainers << "\n";
	std::cout << "Total time taken: "
			  << std::chrono::duration_cast<std::chrono::seconds>(
					 std::chrono::steady_clock::now() - startTime)
					 .count()
			  << " s\n";
	for (const std::size_t groupReadContainers : containersReadInGroups) {
		std::cout << "Total read containers: " << groupReadContainers << "\n";
		std::cout << "Lost containers: " << (totalWrittenContainers - groupReadContainers) << "\n";
		std::cout << "Lost containers percentage: "
				  << (100.0 * (totalWrittenContainers - groupReadContainers)
					  / totalWrittenContainers)
				  << "%\n";
	}
}

template<typename OutputStorageType>
void makeTestGroup(const bool immitateWork)
{
	std::cout << "1 Writer, 1 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(1, {1}, immitateWork);

	std::cout << "32 Writers, 1 Group 32 Readers" << (immitateWork ? " With Work" : " No Work")
			  << "\n";
	makeTest<OutputStorageType>(32, {32}, immitateWork);

	std::cout << "4 Writers, 1 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(4, {1}, immitateWork);

	std::cout << "32 Writers, 1 Reader" << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(32, {1}, immitateWork);

	std::cout << "1 Writer, 1 Group 2 Readers" << (immitateWork ? " With Work" : " No Work")
			  << "\n";
	makeTest<OutputStorageType>(1, {2}, immitateWork);

	std::cout << "4 Writers, 2 Groups 2 Readers" << (immitateWork ? " With Work" : " No Work")
			  << "\n";
	makeTest<OutputStorageType>(4, {2, 2}, immitateWork);
}

template<typename OutputStorageType>
void stressTest(const bool immitateWork)
{
	std::cout << "Stress Test: 32 Writers, 1 Group 32 Readers"
			  << (immitateWork ? " With Work" : " No Work") << "\n";
	makeTest<OutputStorageType>(32, {32}, immitateWork, 100'000'000);
}

TEST(TestOutputStorage, LFNBStorageTestStressNoWorkImmitation)
{
	stressTest<ipxp::output::LFNBOutputStorage>(false);
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
