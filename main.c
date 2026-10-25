#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define ALPHABET_SIZE 256
#define MAX_IP_LEN 16
#define HASH_TABLE_SIZE 1024

/* ==========================================
   1. DATA STRUCTURE DEFINITIONS
   ========================================== */

// Aho-Corasick Trie Node
typedef struct TrieNode {
    struct TrieNode* children[ALPHABET_SIZE];
    struct TrieNode* fail_link;
    char* threat_name; 
} TrieNode;

// Sliding Window Event Node
typedef struct EventNode {
    long timestamp;
    struct EventNode* next;
} EventNode;

// Sliding Window Queue
typedef struct SlidingWindow {
    EventNode* head;
    EventNode* tail;
    int current_count;
} SlidingWindow;

// Hash Table Node for IP tracking
typedef struct HashNode {
    char ip_address[MAX_IP_LEN];
    SlidingWindow* events;
    struct HashNode* next;
} HashNode;

// Hash Table Array
typedef struct HashTable {
    HashNode* buckets[HASH_TABLE_SIZE];
} HashTable;


/* ==========================================
   2. BEHAVIORAL TRACKING & HASH TABLE
   ========================================== */

SlidingWindow* create_sliding_window() {
    SlidingWindow* window = (SlidingWindow*)malloc(sizeof(SlidingWindow));
    window->head = window->tail = NULL;
    window->current_count = 0;
    return window;
}

void enqueue_event(SlidingWindow* window, long timestamp) {
    EventNode* new_event = (EventNode*)malloc(sizeof(EventNode));
    new_event->timestamp = timestamp;
    new_event->next = NULL;
    if (window->tail == NULL) {
        window->head = window->tail = new_event;
    } else {
        window->tail->next = new_event;
        window->tail = new_event;
    }
    window->current_count++;
}

void trim_expired_events(SlidingWindow* window, long current_time, int time_window) {
    long cutoff_time = current_time - time_window;
    while (window->head != NULL && window->head->timestamp < cutoff_time) {
        EventNode* temp = window->head;
        window->head = window->head->next;
        if (window->head == NULL) window->tail = NULL;
        free(temp);
        window->current_count--;
    }
}

// Simple hash function for IP strings (djb2 algorithm)
unsigned int hash_ip(const char* ip) {
    unsigned int hash = 5381;
    int c;
    while ((c = *ip++)) hash = ((hash << 5) + hash) + c;
    return hash % HASH_TABLE_SIZE;
}

HashTable* create_hash_table() {
    HashTable* table = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < HASH_TABLE_SIZE; i++) table->buckets[i] = NULL;
    return table;
}

// Get existing sliding window for an IP, or create one if it doesn't exist
SlidingWindow* get_or_create_ip_record(HashTable* table, const char* ip) {
    unsigned int index = hash_ip(ip);
    HashNode* current = table->buckets[index];
    
    while (current != NULL) {
        if (strcmp(current->ip_address, ip) == 0) return current->events;
        current = current->next;
    }
    
    HashNode* new_node = (HashNode*)malloc(sizeof(HashNode));
    strcpy(new_node->ip_address, ip);
    new_node->events = create_sliding_window();
    new_node->next = table->buckets[index];
    table->buckets[index] = new_node;
    
    return new_node->events;
}


/* ==========================================
   3. AHO-CORASICK AUTOMATON (SIGNATURES)
   ========================================== */

TrieNode* create_trie_node() {
    TrieNode* node = (TrieNode*)malloc(sizeof(TrieNode));
    node->fail_link = NULL;
    node->threat_name = NULL;
    for (int i = 0; i < ALPHABET_SIZE; i++) node->children[i] = NULL;
    return node;
}

void insert_pattern(TrieNode* root, const char* pattern, const char* threat_name) {
    TrieNode* current = root;
    for (int i = 0; pattern[i] != '\0'; i++) {
        unsigned char index = (unsigned char)pattern[i];
        if (current->children[index] == NULL) {
            current->children[index] = create_trie_node();
        }
        current = current->children[index];
    }
    if (current->threat_name == NULL) current->threat_name = strdup(threat_name);
}

// Build failure links using Breadth-First Search (BFS)
void build_failure_links(TrieNode* root) {
    root->fail_link = root;
    TrieNode* queue[10000]; // Simple fixed-size queue for BFS
    int head = 0, tail = 0;

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (root->children[i] != NULL) {
            root->children[i]->fail_link = root;
            queue[tail++] = root->children[i];
        } else {
            root->children[i] = root; // Optimizes search transitions
        }
    }

    while (head < tail) {
        TrieNode* current = queue[head++];
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            if (current->children[i] != NULL) {
                TrieNode* child = current->children[i];
                TrieNode* fail = current->fail_link;
                
                while (fail != root && fail->children[i] == NULL) {
                    fail = fail->fail_link;
                }
                
                if (fail->children[i] != NULL && fail->children[i] != child) {
                    child->fail_link = fail->children[i];
                } else {
                    child->fail_link = root;
                }
                queue[tail++] = child;
            }
        }
    }
}

// Scan a log payload for malicious signatures
void scan_for_signatures(TrieNode* root, const char* log_payload) {
    TrieNode* current = root;
    for (int i = 0; log_payload[i] != '\0'; i++) {
        unsigned char c = (unsigned char)log_payload[i];
        
        while (current != root && current->children[c] == NULL) {
            current = current->fail_link;
        }
        if (current->children[c] != NULL) {
            current = current->children[c];
        }
        
        TrieNode* temp = current;
        while (temp != root) {
            if (temp->threat_name != NULL) {
                printf("[SIGNATURE ALERT] %s found ending at index %d\n", temp->threat_name, i);
            }
            temp = temp->fail_link;
        }
    }
}


/* ==========================================
   4. MAIN SYSTEM INGESTION ENGINE
   ========================================== */

// Process incoming log for both Exact Signatures and Behavioral Rules
void process_log(TrieNode* root, HashTable* ip_table, long timestamp, const char* ip, const char* payload) {
    printf("Processing Log: [%ld] %s - %s\n", timestamp, ip, payload);
    
    // 1. Check for Exact Signatures (Aho-Corasick)
    scan_for_signatures(root, payload);
    
    // 2. Check for Behavioral Rules (E.g., Brute Force Attack: >3 failed logins in 60s)
    if (strstr(payload, "Failed password") != NULL) {
        int threshold = 3;
        int time_window = 60;
        
        SlidingWindow* window = get_or_create_ip_record(ip_table, ip);
        enqueue_event(window, timestamp);
        trim_expired_events(window, timestamp, time_window);
        
        if (window->current_count >= threshold) {
            printf("[BEHAVIORAL ALERT] Brute-force detected from IP %s (%d fails in %ds)\n", 
                   ip, window->current_count, time_window);
        }
    }
    printf("\n");
}

int main() {
    // 1. Initialize Systems
    TrieNode* root = create_trie_node();
    HashTable* ip_table = create_hash_table();
    
    // 2. Load Threat Signatures ($P$)
    insert_pattern(root, "' OR 1=1 --", "SQL Injection");
    insert_pattern(root, "DROP TABLE", "Destructive SQL");
    insert_pattern(root, "nmap -sS", "Nmap Stealth Scan");
    
    // 3. Compile Aho-Corasick Failure Links
    build_failure_links(root);
    
    // 4. Simulate Incoming Log Stream ($L$)
    long current_time = 1700000000;
    
    // Simulating a Brute-Force Attack
    process_log(root, ip_table, current_time + 1, "192.168.1.50", "Failed password for root");
    process_log(root, ip_table, current_time + 15, "192.168.1.50", "Failed password for root");
    process_log(root, ip_table, current_time + 35, "192.168.1.50", "Failed password for admin"); // Triggers Alert
    
    // Simulating an SQL Injection
    process_log(root, ip_table, current_time + 40, "10.0.0.99", "GET /login?user=' OR 1=1 --"); // Triggers Alert
    
    // Simulating a normal user (no alert)
    process_log(root, ip_table, current_time + 45, "172.16.0.5", "Accepted publickey for admin");
    
    return 0;
}