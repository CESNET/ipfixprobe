/**
 * @file
 * @brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * @author Jiri Havranek <havranek@cesnet.cz>
 * @author Vaclav Bartos <bartos@cesnet.cz>
 * @author Pavel Siska <siska@cesnet.cz>
 * @date 2025
 *
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "unirec.hpp"

#include "fields.h"

#include <algorithm>
#include <string>
#include <vector>
#include <numeric>
#include <ranges>

#include <ipfixprobe/pluginFactory/pluginManifest.hpp>
#include <ipfixprobe/pluginFactory/pluginRegistrar.hpp>
#include <ipfixprobe/plugin.hpp>
#include <libtrap/trap.h>
#include <unirec/unirec.h>

namespace ipxp {

static const PluginManifest unirecPluginManifest = {
	.name = "unirec",
	.description = "Output plugin for unirec export",
	.pluginVersion = "1.0.0",
	.apiVersion = "1.0.0",
	.usage =
		[]() {
			UnirecOptParser parser;
			parser.usage(std::cout);
		},
};

#define BASIC_FLOW_TEMPLATE                                                                        \
	"SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,PACKETS_REV,BYTES_REV,TIME_FIRST,"     \
	"TIME_LAST,TCP_FLAGS,TCP_FLAGS_REV,DIR_BIT_FIELD,SRC_MAC,DST_MAC" /* LINK_BIT_FIELD or ODID    \
																		 will be added at init. */

#define PACKET_TEMPLATE "SRC_MAC,DST_MAC,ETHERTYPE,TIME"

UR_FIELDS(
	ipaddr DST_IP,
	ipaddr SRC_IP,
	uint64 BYTES,
	uint64 BYTES_REV,
	uint64 LINK_BIT_FIELD,
	uint32 ODID,
	time TIME_FIRST,
	time TIME_LAST,
	uint32 PACKETS,
	uint32 PACKETS_REV,
	uint16 DST_PORT,
	uint16 SRC_PORT,
	uint8 DIR_BIT_FIELD,
	uint8 PROTOCOL,
	uint8 TCP_FLAGS,
	uint8 TCP_FLAGS_REV,

	macaddr SRC_MAC,
	macaddr DST_MAC)

/**
 * \brief Constructor.
 */
/*UnirecExporter::UnirecExporter(const std::string& params, ProcessPlugins& plugins)
	: m_basic_idx(-1)
	, m_ext_cnt(0)
	, m_ifc_map(nullptr)
	, m_tmplts(nullptr)
	, m_records(nullptr)
	, m_ifc_cnt(0)
	, m_ext_id_flgs(nullptr)
	, m_eof(false)
	, m_odid(false)
	, m_link_bit_field(0)
	, m_dir_bit_field(0)
{
	init(params.c_str(), plugins);
}*/

UnirecExporter::~UnirecExporter()
{
	close();
}

/**
 * \brief Count trap interfaces.
 * \param [in] argc Number of parameters.
 * \param [in] argv Pointer to parameters.
 * \return Number of trap interfaces.
 */
static int count_trap_interfaces(const char* spec)
{
	int ifc_cnt = 1;
	if (spec != nullptr) {
		while (*spec) { // Count number of specified interfaces.
			if (*(spec++) == TRAP_IFC_DELIMITER) {
				ifc_cnt++;
			}
		}
		return ifc_cnt;
	}

	return ifc_cnt;
}

int UnirecExporter::init_trap(std::string& ifcs, int verbosity)
{
	trap_ifc_spec_t ifc_spec;
	std::vector<char> spec_str(ifcs.c_str(), ifcs.c_str() + ifcs.size() + 1);
	char* argv[] = {"-i", spec_str.data()};
	int argc = 2;
	int ifc_cnt = count_trap_interfaces(ifcs.c_str());

	if (trap_parse_params(&argc, argv, &ifc_spec) != TRAP_E_OK) {
		trap_free_ifc_spec(ifc_spec);
		std::string err_msg = "parsing parameters for TRAP failed";
		if (trap_last_error_msg) {
			err_msg += std::string(": ") + trap_last_error_msg;
		}
		throw PluginError(err_msg);
	}
	trap_module_info_t module_info = {"ipfixprobe", "Output plugin for ipfixprobe", 0, ifc_cnt};
	if (trap_init(&module_info, ifc_spec) != TRAP_E_OK) {
		trap_free_ifc_spec(ifc_spec);
		std::string err_msg = "error in TRAP initialization: ";
		if (trap_last_error_msg) {
			err_msg += std::string(": ") + trap_last_error_msg;
		}
		throw PluginError(err_msg);
	}
	trap_free_ifc_spec(ifc_spec);

	if (verbosity > 0) {
		trap_set_verbose_level(verbosity - 1);
	}
	for (int i = 0; i < ifc_cnt; i++) {
		trap_ifcctl(TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
	}
	return ifc_cnt;
}

template<typename T>
constexpr bool always_false = false;

template<typename Type>
static ur_field_id_t defineField(std::string_view name) noexcept
{
	if constexpr (std::is_same_v<Type, uint8_t>) {
		return ur_define_field(name.data(), UR_TYPE_UINT8);
	} else if constexpr (std::is_same_v<Type, uint16_t>) {
		return ur_define_field(name.data(), UR_TYPE_UINT16);
	} else if constexpr (std::is_same_v<Type, uint32_t>) {
		return ur_define_field(name.data(), UR_TYPE_UINT32);
	} else if constexpr (std::is_same_v<Type, uint64_t>) {
		return ur_define_field(name.data(), UR_TYPE_UINT64);
	} else if constexpr (std::is_same_v<Type, int8_t>) {
		return ur_define_field(name.data(), UR_TYPE_INT8);
	} else if constexpr (std::is_same_v<Type, int16_t>) {
		return ur_define_field(name.data(), UR_TYPE_INT16);
	} else if constexpr (std::is_same_v<Type, int32_t>) {
		return ur_define_field(name.data(), UR_TYPE_INT32);
	} else if constexpr (std::is_same_v<Type, int64_t>) {
		return ur_define_field(name.data(), UR_TYPE_INT64);
	} else if constexpr (std::is_same_v<Type, float>) {
		return ur_define_field(name.data(), UR_TYPE_FLOAT);
	} else if constexpr (std::is_same_v<Type, double>) {
		return ur_define_field(name.data(), UR_TYPE_DOUBLE);
	} else if constexpr (std::is_same_v<Type, std::string_view>) {
		return ur_define_field(name.data(), UR_TYPE_STRING);
	} else if constexpr (std::is_same_v<Type, MACAddress>) {
		return ur_define_field(name.data(), UR_TYPE_MAC);
	} else if constexpr (std::is_same_v<Type, IPAddress>) {
		return ur_define_field(name.data(), UR_TYPE_IP);
	} else if constexpr (std::is_same_v<Type, Timestamp>) {
		return ur_define_field(name.data(), UR_TYPE_TIME);
	} else if constexpr (std::is_same_v<Type, std::span<const std::byte>>) {
		return ur_define_field(name.data(), UR_TYPE_BYTES);
	} else if constexpr (std::is_same_v<Type, std::span<const std::string>>) {
		return ur_define_field(name.data(), UR_TYPE_STRING);
	} else if constexpr (std::is_same_v<Type, std::span<const MACAddress>>) {
		return ur_define_field(name.data(), UR_TYPE_A_MAC);
	} else if constexpr (std::is_same_v<Type, std::span<const IPAddress>>) {
		return ur_define_field(name.data(), UR_TYPE_A_IP);
	} else if constexpr (std::is_same_v<Type, std::span<const Timestamp>>) {
		return ur_define_field(name.data(), UR_TYPE_A_TIME);
	} else if constexpr (std::is_same_v<Type, std::span<const double>>) {
		return ur_define_field(name.data(), UR_TYPE_A_DOUBLE);
	} else if constexpr (std::is_same_v<Type, std::span<const float>>) {
		return ur_define_field(name.data(), UR_TYPE_A_FLOAT);
	} else if constexpr (std::is_same_v<Type, std::span<const uint8_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_UINT8);
	} else if constexpr (std::is_same_v<Type, std::span<const uint16_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_UINT16);
	} else if constexpr (std::is_same_v<Type, std::span<const uint32_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_UINT32);
	} else if constexpr (std::is_same_v<Type, std::span<const uint64_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_UINT64);
	} else if constexpr (std::is_same_v<Type, std::span<const int8_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_INT8);
	} else if constexpr (std::is_same_v<Type, std::span<const int16_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_INT16);
	} else if constexpr (std::is_same_v<Type, std::span<const int32_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_INT32);
	} else if constexpr (std::is_same_v<Type, std::span<const int64_t>>) {
		return ur_define_field(name.data(), UR_TYPE_A_INT64);
	} else {
		static_assert(always_false<Type>, "Unsupported type");
	}

	__builtin_unreachable();
} 

void UnirecExporter::init(const char* params)
{
	UnirecOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.m_help) {
		trap_print_ifc_spec_help();
		throw PluginExit();
	}
	if (parser.m_ifc.empty()) {
		throw PluginError("specify libtrap interface specifier");
	}
	m_odid = parser.m_odid;
	m_eof = parser.m_eof;
	m_link_bit_field = parser.m_id;
	m_dir_bit_field = parser.m_dir;
	m_group_map = parser.m_ifc_map;
	m_ifc_cnt = init_trap(parser.m_ifc, parser.m_verbose);
	m_ext_cnt = m_plugins.size();

	try {
		m_tmplts = new ur_template_t*[m_ifc_cnt];
		m_records = new void*[m_ifc_cnt];
		m_ifc_map = new int[m_ext_cnt];
		m_ext_id_flgs = new int[m_ext_cnt];
	} catch (std::bad_alloc& e) {
		throw PluginError("not enough memory");
	}
	for (size_t i = 0; i < m_ifc_cnt; i++) {
		m_tmplts[i] = nullptr;
		m_records[i] = nullptr;
	}
	for (size_t i = 0; i < m_ext_cnt; i++) {
		m_ifc_map[i] = -1;
	}

	std::ranges::transform(m_fieldManager.getBiflowFields(), std::back_inserter(m_field_ids),
	[&](const FieldDescriptor& fieldDescriptor) {
		return std::visit(
			[&](const auto& variant) {
				return std::visit([&](const auto& accessor) {
					return defineField<decltype(accessor(nullptr))>(fieldDescriptor.getName());
				}, variant);
			}, fieldDescriptor.getValueGetter());
	});
}

void UnirecExporter::create_tmplt(int ifc_idx, const char* tmplt_str)
{
	char* error = nullptr;
	m_tmplts[ifc_idx] = ur_create_output_template(ifc_idx, tmplt_str, &error);
	if (m_tmplts[ifc_idx] == nullptr) {
		std::string tmp = error;
		free(error);
		free_unirec_resources();
		throw PluginError(tmp);
	}
}

void UnirecExporter::init(const char* params, const std::vector<ProcessPluginEntry>& plugins)
{
	init(params);

	std::string basic_tmplt = BASIC_FLOW_TEMPLATE;
	if (m_odid) {
		basic_tmplt += ",ODID";
	} else {
		basic_tmplt += ",LINK_BIT_FIELD";
	}

	if (m_group_map.empty()) {
		if (m_ifc_cnt == 1 && plugins.empty()) {
			m_basic_idx = 0;

			create_tmplt(m_basic_idx, basic_tmplt.c_str());
		} else if (m_ifc_cnt == 1 && plugins.size() == 1) {
			m_group_map[0] = std::vector<std::string>({plugins[0].name});
		} else {
			throw PluginError("specify plugin-interface mapping");
		}
	}

	if (m_ifc_cnt != 1 && m_ifc_cnt != m_group_map.size()) {
		throw PluginError("number of interfaces and plugin groups differ");
	}

	for (auto& m : m_group_map) {
		unsigned ifc_idx = m.first;
		std::vector<std::string>& group = m.second;

		// Find plugin for each plugin in group
		std::vector<std::pair<std::string_view, std::shared_ptr<ProcessPlugin>>> plugin_group;
		for (auto& g : group) {
			std::shared_ptr<ProcessPlugin> plugin = nullptr;
			for (auto& p : plugins) {
				std::string name = p.name;
				if (g == name) {
					plugin = p.plugin;
					break;
				}
			}
			if (m_tmplts[ifc_idx] != nullptr || (m_basic_idx >= 0 && g == BASIC_PLUGIN_NAME)) {
				throw PluginError("plugin can be specified only one time");
			}
			if (group.size() == 1 && g == BASIC_PLUGIN_NAME) {
				m_basic_idx = ifc_idx;
				break;
			}
			if (plugin == nullptr) {
				throw PluginError(g + " plugin is not activated");
			}
			plugin_group.push_back({g, plugin});
		}

		// Create output template string and extension->ifc map
		std::string tmplt_str = basic_tmplt;
		for (auto [name, plugin] : plugin_group) {
			//RecordExt* ext = p->get_ext();
			//tmplt_str += std::string(",") + ext->get_unirec_tmplt();
			auto fields = m_fieldManager.getBiflowFields() | std::views::filter([&](const auto& field) {
				return field.getGroup() == name;
			}) | std::views::transform(&FieldDescriptor::getName);
			tmplt_str += std::accumulate(fields.begin(), fields.end(), std::string{}, [](const auto& a, const auto& b) {
				return a + (a.empty() ? "" : ",") + b.data();
			});
			int ext_id = std::ranges::find_if(plugins, [&](const auto &p) {
    			return p.plugin.get() == plugin.get();}) - plugins.begin();
			//int ext_id = ext->m_ext_id;
			//delete ext;
			/*if (ext_id < 0) {
				continue;
			}*/
			if (m_ifc_map[ext_id] >= 0) {
				throw PluginError(
					"plugin output can be exported only to one interface at the moment");
			}
			m_ifc_map[ext_id++] = ifc_idx;
		}

		create_tmplt(ifc_idx, tmplt_str.c_str());
	}

	for (size_t i = 0; i < m_ifc_cnt; i++) { // Create unirec records.
		m_records[i] = ur_create_record(
			m_tmplts[i],
			(static_cast<ssize_t>(i) == m_basic_idx ? 0 : UR_MAX_SIZE));

		if (m_records[i] == nullptr) {
			free_unirec_resources();
			throw PluginError("not enough memory");
		}
	}

	m_group_map.clear();
}

void UnirecExporter::close()
{
	if (m_eof) {
		for (size_t i = 0; i < m_ifc_cnt; i++) {
			trap_send(i, "", 1);
		}
	}
	trap_finalize();
	free_unirec_resources();

	m_basic_idx = -1;
	m_ifc_cnt = 0;
	delete[] m_ext_id_flgs;
}

/**
 * \brief Free unirec templates and unirec records.
 */
void UnirecExporter::free_unirec_resources()
{
	if (m_tmplts) {
		for (size_t i = 0; i < m_ifc_cnt; i++) {
			if (m_tmplts[i] != nullptr) {
				ur_free_template(m_tmplts[i]);
			}
		}
		delete[] m_tmplts;
		m_tmplts = nullptr;
	}
	if (m_records) {
		for (size_t i = 0; i < m_ifc_cnt; i++) {
			if (m_records[i] != nullptr) {
				ur_free_record(m_records[i]);
			}
		}
		delete[] m_records;
		m_records = nullptr;
	}
	if (m_ifc_map) {
		delete[] m_ifc_map;
		m_ifc_map = nullptr;
	}
}

/*template<typename T>
static void
fillFromVectorVariant(const FieldDescriptor& field, const VectorAccessor<T>& accessor, const void* data)
{
	std::cout << "[" << field.getGroup() << "] " << field.getName() << ": [";

	bool first = true;
	for (const auto& value : accessor(data)) {
		if (!first)
			std::cout << ", ";
		std::cout << value;
		first = false;
	}

	std::cout << "]\n";
}*/

void UnirecExporter::fillFromScalarVariant(const FieldDescriptor& field, const ScalarValueGetter& variant, const void* data, ur_template_t* tmplt_ptr, void* record_ptr) noexcept
{
	const auto visitor = [&](const auto& accessor) {
		if constexpr (std::is_same_v<std::decay_t<decltype(accessor(data))>, std::string_view>) {
			ur_set_string(tmplt_ptr, record_ptr, m_field_ids[field.getBitIndex()], accessor(data).data());
		} else {
			*reinterpret_cast<decltype(accessor(data))*>(
				ur_get_ptr_by_id(tmplt_ptr, record_ptr, m_field_ids[field.getBitIndex()])) = accessor(data);
		}
	};
	std::visit(visitor, variant);
}

void UnirecExporter::fillFromVectorVariant(const FieldDescriptor& field, const VectorValueGetter& variant, const void* data, ur_template_t* tmplt_ptr, void* record_ptr) noexcept
{
	const auto visitor = [&](const auto& accessor) {
		if constexpr (std::is_same_v<std::decay_t<decltype(accessor(data))>, std::span<const Timestamp>>) {
			ur_set_var_len(tmplt_ptr, record_ptr, m_field_ids[field.getBitIndex()], accessor(data).size() * sizeof(ur_time_t));
			auto* buffer = reinterpret_cast<ur_time_t*>(ur_get_ptr_by_id(tmplt_ptr, record_ptr, m_field_ids[field.getBitIndex()]));
			std::ranges::transform(accessor(data), buffer, [](const Timestamp& ts) {
				return ur_time_from_sec_usec(ts.toTimeval().tv_sec, ts.toTimeval().tv_usec);
			});
		} else if constexpr (std::is_same_v<std::decay_t<decltype(accessor(data))>, std::span<const std::string>>) {
			const std::size_t totalLength = std::accumulate(accessor(data).begin(), accessor(data).end(), 0,
				[](std::size_t sum, const std::string& str) { return sum + str.size() + sizeof(';'); });
			ur_set_var_len(tmplt_ptr, record_ptr, m_field_ids[field.getBitIndex()], totalLength);
			auto* buffer = reinterpret_cast<char*>(ur_get_ptr_by_id(tmplt_ptr, record_ptr, m_field_ids[field.getBitIndex()]));
			std::ranges::for_each(accessor(data), [&buffer](const std::string& str) {
				std::memcpy(buffer, str.data(), str.size());
				buffer += str.size();
				*(buffer++) = ';';
			});
		} /*else if constexpr (std::is_same_v<std::decay_t<decltype(accessor(data))>, std::span<const IPAddress>>) {}*/
		else {
			ur_set_var(
				tmplt_ptr,
				record_ptr,
				m_field_ids[field.getBitIndex()],
				accessor(data).data(),
				accessor(data).size() * sizeof(decltype(accessor(data)[0])));
		}
	};
	std::visit(visitor, variant);
}


void UnirecExporter::processRecord(FlowRecordUniquePtr& flowRecord)
{
	if (m_basic_idx >= 0) { // Process basic flow.
		ur_template_t* tmplt_ptr = m_tmplts[m_basic_idx];
		void* record_ptr = m_records[m_basic_idx];

		ur_clear_varlen(tmplt_ptr, record_ptr);
		fill_basic_flow(*flowRecord, tmplt_ptr, record_ptr);
		trap_send(
			m_basic_idx,
			record_ptr,
			ur_rec_fixlen_size(tmplt_ptr) + ur_rec_varlen_size(tmplt_ptr, record_ptr));
	}

	m_seen++;
	uint64_t tmplt_dbits = 0; // templates dirty bits
	memset(m_ext_id_flgs, 0, sizeof(int) * m_ext_cnt); // in case one flow has multiple extension of same type
	int ext_processed_cnd = 0;

	std::ranges::for_each(m_fieldManager.getBiflowFields(), [&, index = 0](const FieldDescriptor& fieldDescriptor) mutable {
		ext_processed_cnd++;
		std::cout << "Bit index is " << fieldDescriptor.getBitIndex() << "\n";
		const void* pluginExportData = flowRecord->getPluginContext(fieldDescriptor.getBitIndex());
		if (!fieldDescriptor.isInRecord(*flowRecord)) {
			return;
		}


		const int ifc_num = m_ifc_map[fieldDescriptor.getBitIndex()];
		if (ifc_num < 0) {
			return;
		}

		ur_template_t* tmplt_ptr = m_tmplts[ifc_num];
		void* record_ptr = m_records[ifc_num];

		if ((tmplt_dbits & (1 << ifc_num)) == 0) {
			ur_clear_varlen(tmplt_ptr, record_ptr);
			memset(record_ptr, 0, ur_rec_fixlen_size(tmplt_ptr));
			tmplt_dbits |= (1 << ifc_num);
		}

		if (m_ext_id_flgs[index] == 1) {
			// send the previously filled unirec record
			trap_send(ifc_num, record_ptr, ur_rec_size(tmplt_ptr, record_ptr));
		} else {
			m_ext_id_flgs[index] = 1;
		}

		const auto& getter = fieldDescriptor.getValueGetter();

		std::visit(
			[&](const auto& variant) {
				using GetterT = std::decay_t<decltype(variant)>;
				if constexpr (std::is_same_v<GetterT, ScalarValueGetter>) {
					fillFromScalarVariant(fieldDescriptor, variant, pluginExportData, tmplt_ptr, record_ptr);
				} else if constexpr (std::is_same_v<GetterT, VectorValueGetter>) {
					fillFromVectorVariant(fieldDescriptor, variant, pluginExportData, tmplt_ptr, record_ptr);
				}
			},
			getter);
	});

	// send the last record with all plugin data
	for (size_t ifc_num = 0; ifc_num < m_ifc_cnt && !(m_basic_idx >= 0) && ext_processed_cnd > 0;
		 ifc_num++) {
		ur_template_t* tmplt_ptr = m_tmplts[ifc_num];
		void* record_ptr = m_records[ifc_num];
		trap_send(ifc_num, record_ptr, ur_rec_size(tmplt_ptr, record_ptr));
	}

	return;
}

//int UnirecExporter::export_flow(const Flow& flow)
//{
	/*while (ext != nullptr) {
		if (ext->m_ext_id >= static_cast<int>(m_ext_cnt)) {
			throw PluginError("encountered invalid extension id");
		}
		ext_processed_cnd++;
		int ifc_num = m_ifc_map[ext->m_ext_id];
		if (ifc_num >= 0) {
			tmplt_ptr = m_tmplts[ifc_num];
			record_ptr = m_records[ifc_num];

			if ((tmplt_dbits & (1 << ifc_num)) == 0) {
				ur_clear_varlen(tmplt_ptr, record_ptr);
				memset(record_ptr, 0, ur_rec_fixlen_size(tmplt_ptr));
				tmplt_dbits |= (1 << ifc_num);
			}

			if (m_ext_id_flgs[ext->m_ext_id] == 1) {
				// send the previously filled unirec record
				trap_send(ifc_num, record_ptr, ur_rec_size(tmplt_ptr, record_ptr));
			} else {
				m_ext_id_flgs[ext->m_ext_id] = 1;
			}

			fill_basic_flow(flow, tmplt_ptr, record_ptr);
			ext->fill_unirec(
				tmplt_ptr,
				record_ptr); // Add each extension header into unirec record.
		}
		ext = ext->m_next;
}*/

//}

/**
 * \brief Fill record with basic flow fields.
 * \param [in] flow Flow record.
 * \param [in] tmplt_ptr Pointer to unirec template.
 * \param [out] record_ptr Pointer to unirec record.
 */
void UnirecExporter::fill_basic_flow(const FlowRecord& flow, ur_template_t* tmplt_ptr, void* record_ptr)
{
	ur_time_t tmp_time;

	if (flow.flowKey.srcIp.isIPv4()) {
		ur_set(tmplt_ptr, record_ptr, F_SRC_IP, ip_from_4_bytes_be(reinterpret_cast<const char*>(flow.flowKey.srcIp.u8.data())));
		ur_set(tmplt_ptr, record_ptr, F_DST_IP, ip_from_4_bytes_be(reinterpret_cast<const char*>(flow.flowKey.dstIp.u8.data())));
	} else {
		ur_set(tmplt_ptr, record_ptr, F_SRC_IP, ip_from_16_bytes_be(reinterpret_cast<const char*>(flow.flowKey.srcIp.u8.data())));
		ur_set(tmplt_ptr, record_ptr, F_DST_IP, ip_from_16_bytes_be(reinterpret_cast<const char*>(flow.flowKey.dstIp.u8.data())));
	}

	tmp_time = ur_time_from_sec_usec(flow.timeCreation.toTimeval().tv_sec, flow.timeCreation.toTimeval().tv_usec);
	ur_set(tmplt_ptr, record_ptr, F_TIME_FIRST, tmp_time);

	tmp_time = ur_time_from_sec_usec(flow.timeLastUpdate.toTimeval().tv_sec, flow.timeLastUpdate.toTimeval().tv_usec);
	ur_set(tmplt_ptr, record_ptr, F_TIME_LAST, tmp_time);

	if (m_odid) {
		ur_set(tmplt_ptr, record_ptr, F_ODID, m_link_bit_field);
	} else {
		ur_set(tmplt_ptr, record_ptr, F_LINK_BIT_FIELD, m_link_bit_field);
	}
	ur_set(tmplt_ptr, record_ptr, F_DIR_BIT_FIELD, m_dir_bit_field);
	ur_set(tmplt_ptr, record_ptr, F_PROTOCOL, flow.flowKey.srcIp.isIPv4() ? 4 : 6);
	ur_set(tmplt_ptr, record_ptr, F_SRC_PORT, flow.flowKey.srcPort);
	ur_set(tmplt_ptr, record_ptr, F_DST_PORT, flow.flowKey.dstPort);
	ur_set(tmplt_ptr, record_ptr, F_PACKETS, flow.directionalData[Direction::Forward].packets);
	ur_set(tmplt_ptr, record_ptr, F_BYTES, flow.directionalData[Direction::Forward].bytes);
	ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS, flow.directionalData[Direction::Forward].tcpFlags.raw);
	ur_set(tmplt_ptr, record_ptr, F_PACKETS_REV, flow.directionalData[Direction::Reverse].packets);
	ur_set(tmplt_ptr, record_ptr, F_BYTES_REV, flow.directionalData[Direction::Reverse].bytes);
	ur_set(tmplt_ptr, record_ptr, F_TCP_FLAGS_REV, flow.directionalData[Direction::Reverse].tcpFlags.raw);

	ur_set(tmplt_ptr, record_ptr, F_DST_MAC, mac_from_bytes(reinterpret_cast<const uint8_t*>(flow.macAddress[Direction::Reverse].address.data())));
	ur_set(tmplt_ptr, record_ptr, F_SRC_MAC, mac_from_bytes(reinterpret_cast<const uint8_t*>(flow.macAddress[Direction::Forward].address.data())));
}

static const PluginRegistrar<UnirecExporter, OutputPluginFactory>
	unirecRegistrar(unirecPluginManifest);

} // namespace ipxp
