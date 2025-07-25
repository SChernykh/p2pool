#ifndef P2POOL_EXTERNAL_SRC_COMMON_SANITIZER_ASAN_INTERFACE_H
#define P2POOL_EXTERNAL_SRC_COMMON_SANITIZER_ASAN_INTERFACE_H

#ifndef ASAN_POISON_MEMORY_REGION
#define ASAN_POISON_MEMORY_REGION(addr, size) __asan_poison_memory_region((addr), (size))
#endif

#ifndef ASAN_UNPOISON_MEMORY_REGION
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) __asan_unpoison_memory_region((addr), (size))
#endif

#define __asan_address_is_poisoned(addr) false

#endif // P2POOL_EXTERNAL_SRC_COMMON_SANITIZER_ASAN_INTERFACE_H
