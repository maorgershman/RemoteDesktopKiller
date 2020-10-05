#define COBJMACROS
#include <WbemCli.h>

#define QUERY \
    L"SELECT * " \
    L"FROM __InstanceCreationEvent " \
    L"WITHIN 1 " \
    L"WHERE TargetInstance ISA 'Win32_Process' and " \
    L"(TargetInstance.Name = 'DWRCS.exe' or TargetInstance.Name = 'CmRcService.exe')"

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    HRESULT hResult = S_OK;

    /*
        Initialize COM library
    */
    hResult = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hResult))
    {
        return 1;
    }

    /*
        Set general COM security levels
    */
    hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hResult))
    {
        CoUninitialize();
        return 1;
    }

    /*
        Obtain the initial locator to WMI
    */
    IWbemLocator* pLocator = NULL;
    hResult = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hResult))
    {
        CoUninitialize();
        return 1;
    }

    /*
        Connect to WMI
    */
    IWbemServices* pServices = NULL;
    hResult = IWbemLocator_ConnectServer(pLocator, L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    if (FAILED(hResult))
    {
        IWbemLocator_Release(pLocator);
        CoUninitialize();
        return 1;
    }

    /*
        Handle events
    */
    IEnumWbemClassObject* pEnumerator = NULL;
    hResult = IWbemServices_ExecNotificationQuery(pServices, L"WQL", QUERY, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator);
    if (FAILED(hResult))
    {
        IWbemServices_Release(pServices);
        IWbemLocator_Release(pLocator);
        CoUninitialize();
        return 1;
    }

    while (TRUE)
    {
        IWbemClassObject* pObject = NULL;
        {
            ULONG ulReturned = 0UL;
            IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1UL, &pObject, &ulReturned);

            if (ulReturned == 0)
            {
                break;
            }
        }

        /*
            Get the TargetInstance property from the event's object
        */
        IWbemClassObject* pTargetInstance = NULL;
        VARIANT variantTargetInstance;
        {
            IWbemClassObject_Get(pObject, L"TargetInstance", 0, &variantTargetInstance, NULL, NULL);
            pTargetInstance = (IWbemClassObject*)variantTargetInstance.punkVal;
        }

        /*
            Get the PID from the TargetInstance's object
        */
        ULONG pid = 0UL;
        {
            VARIANT variantPID;
            IWbemClassObject_Get(pTargetInstance, L"ProcessId", 0, &variantPID, NULL, NULL);
            pid = variantPID.ulVal;
            VariantClear(&variantPID);
        }

        /*
            Terminate the process
        */
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }

        VariantClear(&variantTargetInstance);
        IWbemClassObject_Release(pObject);
    }

    IWbemClassObject_Release(pEnumerator);
    IWbemServices_Release(pServices);
    IWbemLocator_Release(pLocator);
    CoUninitialize();

    return 0;
}