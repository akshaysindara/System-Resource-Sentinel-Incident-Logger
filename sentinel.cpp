#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "sqlite3.h"
#include <string>
#include <thread>
#include <chrono>

sqlite3* db;

void initDB() {
    sqlite3_open("incidents.db", &db);
    const char* sql = "CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ram_usage REAL, top_process TEXT, process_ram_mb REAL);";
    sqlite3_exec(db, sql, 0, 0, 0);
}

void logToDB(double ram, const std::string& processName, double processRamMB) {
    std::string sql = "INSERT INTO logs (ram_usage, top_process, process_ram_mb) VALUES (" + 
                      std::to_string(ram) + ", '" + processName + "', " + std::to_string(processRamMB) + ");";
    sqlite3_exec(db, sql.c_str(), 0, 0, 0);
}

void getTopProcess(std::string& topProcessName, double& topRamMB) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    SIZE_T maxMem = 0;
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    if (pmc.WorkingSetSize > maxMem) {
                        maxMem = pmc.WorkingSetSize;
                        topProcessName = pe32.szExeFile;
                        topRamMB = (double)maxMem / (1024 * 1024);
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

void monitorSystem() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    
    while(true) {
        GlobalMemoryStatusEx(&memInfo);
        DWORDLONG physMemUsed = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
        double ramPercent = (double)physMemUsed / memInfo.ullTotalPhys * 100;
        
        if(ramPercent > 80.0) {
            std::string topProc = "Unknown";
            double topMem = 0.0;
            getTopProcess(topProc, topMem);
            logToDB(ramPercent, topProc, topMem);
            std::cout << "[ALERT] RAM: " << ramPercent << "% | Culprit: " << topProc << " (" << topMem << " MB) - Logged." << std::endl;
        } else {
            std::cout << "[INFO] RAM Usage: " << ramPercent << "%" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

int main() {
    std::cout << "Starting System Resource Sentinel...\n";
    initDB();
    monitorSystem();
    sqlite3_close(db);
    return 0;
}