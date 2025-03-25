# Pintos: Kernel Threads, User Programs, and File System

## Authors
Joshua Yue, Avi Patel, Akshat Kumar  
## Original credit to Ben Pfaff

## Overview  
This project extends the Pintos operating system by implementing key functionalities in three major areas:

1. **Kernel Threads** – Enhancing thread scheduling and synchronization.
2. **User Programs** – Enabling the execution of user-mode processes.
3. **File System** – Implementing a more robust file system with persistence.

Each component builds on the existing Pintos infrastructure to introduce critical OS features.  

---

## Features Implemented

### 1. Kernel Threads  
- Improved scheduling mechanisms, including priority scheduling.  
- Implemented thread synchronization using **locks, semaphores, and condition variables**.  
- Added support for **priority donation** to prevent priority inversion.  

### 2. User Programs  
- Loaded and executed user-space programs using the **process loader**.  
- Implemented **syscalls** to allow user programs to interact with the kernel.  
- Designed a **virtual memory layout** to handle user process memory safely.  
- Ensured proper **argument passing** and stack setup for new processes.  

### 3. File System  
- Extended Pintos’ basic file system with **persistent storage**.  
- Implemented support for **file read/write syscalls**.  
- Introduced **file locking mechanisms** for concurrent access control.  
- Improved performance through **buffer caching**.  

