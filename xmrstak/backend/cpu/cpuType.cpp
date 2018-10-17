
#include "xmrstak/backend/cpu/cpuType.hpp"

#include <cstring>
#include <inttypes.h>
#include <cstdio>


namespace xmrstak
{
namespace cpu
{
	
	Model getModel()
	{
		Model result;

		result.type_name = "IBM POWER8+";

		return result;
	}

} // namespace cpu
} // namespace xmrstak
