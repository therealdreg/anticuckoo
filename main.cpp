#include "stdafx.h"
#include "anticuckoo.h"

int _tmain(int argc, _TCHAR* argv[])
{
	int returnf;

	returnf = AntiCuckoo(argc, argv);
	system("pause");

	return returnf == 0 ? 0 : 1;
}
