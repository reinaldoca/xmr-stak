#pragma once

#include "jconf.hpp"

#include "xmrstak/misc/console.hpp"
#include "xmrstak/jconf.hpp"
#include "xmrstak/misc/configEditor.hpp"
#include "xmrstak/params.hpp"
#include "xmrstak/backend/cryptonight.hpp"
#include <string>

#include <unistd.h>


namespace xmrstak
{
namespace cpu
{

class autoAdjust
{
public:

	bool printConfig()
	{

		const size_t hashMemSizeKB = std::max(
			cn_select_memory(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo()),
			cn_select_memory(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgoRoot())
		) / 1024u;
		const size_t halfHashMemSizeKB = hashMemSizeKB / 2u;

		configEditor configTpl{};

		// load the template of the backend config into a char variable
		const char *tpl =
			#include "./config.tpl"
		;
		configTpl.set( std::string(tpl) );

		std::string conf;


		if(!detectL3Size() || L3KB_size < halfHashMemSizeKB || L3KB_size > (halfHashMemSizeKB * 2048u))
		{
			if(L3KB_size < halfHashMemSizeKB || L3KB_size > (halfHashMemSizeKB * 2048))
				printer::inst()->print_msg(L0, "Autoconf failed: L3 size sanity check failed - %u KB.", L3KB_size);

			conf += std::string("    { \"low_power_mode\" : false, \"int_sqrt\" : true,  \"asm\" : \"off\", \"affine_to_cpu\" : false },\n");
			printer::inst()->print_msg(L0, "Autoconf FAILED. Create config for a single thread. Please try to add new ones until the hashrate slows down.");
		}
		else
		{
			printer::inst()->print_msg(L0, "Autoconf L3 size detected at %u KB.", L3KB_size);

			detectCPUConf();

			printer::inst()->print_msg(L0, "Autoconf core count detected as %u on %s.", corecnt,
				linux_layout ? "Linux" : "Windows");

			uint32_t aff_id = 0;
			for(uint32_t i=0; i < corecnt; i++)
			{
				bool double_mode;

				if(L3KB_size <= 0)
					break;

				double_mode = L3KB_size / hashMemSizeKB > (int32_t)(corecnt-i);

				conf += std::string("    { \"low_power_mode\" : ");
				conf += std::string(double_mode ? "true" : "false");
				conf += std::string(", \"int_sqrt\" : true, \"asm\" : \"auto\", \"affine_to_cpu\" : ");
				conf += std::to_string(aff_id);
				conf += std::string(" },\n");

				if(!linux_layout || old_amd)
				{
					aff_id += 2;

					if(aff_id >= corecnt)
						aff_id = 1;
				}
				else
					aff_id++;

				if(double_mode)
					L3KB_size -= hashMemSizeKB * 2u;
				else
					L3KB_size -= hashMemSizeKB;
			}
		}

		configTpl.replace("CPUCONFIG",conf);
		configTpl.write(params::inst().configFileCPU);
		printer::inst()->print_msg(L0, "CPU configuration stored in file '%s'", params::inst().configFileCPU.c_str());

		return true;
	}

private:
	bool detectL3Size()
	{
		int32_t cpu_info[4];
		char cpustr[13] = {0};

			printer::inst()->print_msg(L0, "Autoconf failed: Unknown CPU type: %s.", cpustr);
			return false;
	}

	void detectCPUConf()
	{
		corecnt = sysconf(_SC_NPROCESSORS_ONLN);
		linux_layout = true;
	}

	int32_t L3KB_size = 0;
	uint32_t corecnt;
	bool old_amd = false;
	bool linux_layout;
};

} // namespace cpu
} // namespace xmrstak
