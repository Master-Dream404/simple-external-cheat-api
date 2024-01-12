# simple-external-cheat-api
simpel tools like spoofaddress, dll injectsion thread spoof &amp; CreateRemoteThread address spoof, and much more 

to use
    void* addr = 0;
    unsigned char pach[1] = { 0x90 };
    Process("test.exe").Open().Protect(NULL, 0x11, 0, 0, std::bind(static_cast<void* (*)(void*, const void*, std::size_t)>(&memcpy), addr, pach, sizeof(pach)));
    Process m_Process("test.exe");
    unsigned char nop[1] = { 0x90 };
    unsigned char pach[5] = { 0x18, 0x91, 0x31, 0x22, 0x1 };
    m_Process.Open();
    m_Process.SpoofAddress("Project.dll", 0x104E8A, nop);
    m_Process.WriteMemory("Project.dll", 0x104E8A, pach);
    LPVOID buff;
    m_Process.ReadMemory<int>(NULL, 0x104E8A, buff);
    m_Process.FreeLibrary("Cheat.dll");
    m_Process.Inject("C:\\m_cheat.dll");
    unsigned char damit[1] = { 0x90 };
    DWORD old;
    m_Process.Protect("m_cheat.dll", 0x18, sizeof(damit), old, std::bind(&WriteProcessMemory, m_Process.GetHandle(),reinterpret_cast<LPVOID>(0x1),nullptr, 0, nullptr));
    m_Process.Close();
