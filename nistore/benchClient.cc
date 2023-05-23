// -*- mode: c++; c-file-style: "k&r"; c-basic-offset: 4 -*-
// vim: set ts=4 sw=4:
/***********************************************************************
 *
 * nistore/benchClient.cc:
 *   Benchmarking client for NiStore.
 *
 **********************************************************************/

#include "nistore/client.h"

using namespace std;


// Function to pick a random key according to some distribution.
int rand_key();
bool ready = false;
double *zipf;
double alpha =0.75;

int numClients = 2;
int duration = 60;
int tLen = 10;
int wPer = 50; // Out of 100
int skew = 0; // difference between real clock and TrueTime
int error = 0; // error bars

vector<string> keys;
string key, value;
int nKeys = 100000;
nistore::Proto mode = nistore::PROTO_UNKNOWN;
const char *configPath = NULL;
const char *keysPath = NULL;
int nShards = 1;

void epoch(int id) {

    nistore::Client client(mode, configPath, nShards);
    
    struct timeval t0, t1, t2, t3, t4;

    int nTransactions = 0; // Number of transactions attempted.
    int tCount = 0; // Number of transaction suceeded.
    double tLatency = 0.0; // Total latency across all transactions.
    int getCount = 0;
    double getLatency = 0.0;
    int putCount = 0;
    double putLatency = 0.0;
    int beginCount = 0;
    double beginLatency = 0.0;
    int commitCount = 0;
    double commitLatency = 0.0;

    gettimeofday(&t0, NULL);
    srand(t0.tv_sec + t0.tv_usec);
    int ret = 0;
    bool status;
    int ttype; // Transaction type.
    vector<int> keyIdx;


    while (1) {
        keyIdx.clear();

        gettimeofday(&t1, NULL);
        client.Begin();
        gettimeofday(&t4, NULL);
        
        beginCount++;
        beginLatency += ((t4.tv_sec - t1.tv_sec)*1000000 + (t4.tv_usec - t1.tv_usec));

        status = true;
        // Decide which type of retwis transaction it is going to be.
        ttype = rand() % 100;
        ttype = 0;

        if (ttype < 5) {
            // 5% - Add user transaction. 1,3
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            sort(keyIdx.begin(), keyIdx.end());
            
            if (!client.Get(keys[keyIdx[0]], value)) {
                Warning("Aborting due to %s %d", keys[keyIdx[0]].c_str(), ret);
                status = false;
            }
            
            for (int i = 0; i < 3 && status; i++) {
                client.Put(keys[keyIdx[i]], keys[keyIdx[i]]);
            }
            ttype = 1;
        } else if (ttype < 20) {
            // 15% - Follow/Unfollow transaction. 2,2
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            sort(keyIdx.begin(), keyIdx.end());

            for (int i = 0; i < 2 && status; i++) {
                if (!client.Get(keys[keyIdx[i]], value)) {
                    Warning("Aborting due to %s %d", keys[keyIdx[i]].c_str(), ret);
                    status = false;
                }
                client.Put(keys[keyIdx[i]], keys[keyIdx[i]]);
            }
            ttype = 2;
        } else if (ttype < 50) {
            // 30% - Post tweet transaction. 3,5
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            keyIdx.push_back(rand_key());
            sort(keyIdx.begin(), keyIdx.end());

            for (int i = 0; i < 3 && status; i++) {
                if (!client.Get(keys[keyIdx[i]], value)) {
                    Warning("Aborting due to %s %d", keys[keyIdx[i]].c_str(), ret);
                    status = false;
                }
                client.Put(keys[keyIdx[i]], keys[keyIdx[i]]);
            }
            for (int i = 0; i < 2; i++) {
                client.Put(keys[keyIdx[i+3]], keys[keyIdx[i+3]]);
            }
            ttype = 3;
        } else {
            // 50% - Get followers/timeline transaction. rand(1,10),0
            int nGets = 1 + rand() % 10;
            for (int i = 0; i < nGets; i++) {
                keyIdx.push_back(rand_key());
            }

            sort(keyIdx.begin(), keyIdx.end());
            for (int i = 0; i < nGets && status; i++) {
                if (!client.Get(keys[keyIdx[i]], value)) {
                    Warning("Aborting due to %s %d", keys[keyIdx[i]].c_str(), ret);
                    status = false;
                }
            }
            ttype = 4;
        }

        gettimeofday(&t3, NULL);
        status = client.Commit();
        gettimeofday(&t2, NULL);

        commitCount++;
        commitLatency += ((t2.tv_sec - t3.tv_sec)*1000000 + (t2.tv_usec - t3.tv_usec));

        long latency = (t2.tv_sec - t1.tv_sec)*1000000 + (t2.tv_usec - t1.tv_usec);

        // fprintf(stderr, "%d %ld.%06ld %ld.%06ld %ld %d\n", nTransactions+1, t1.tv_sec,
        //         (long)t1.tv_usec, t2.tv_sec, (long)t2.tv_usec, latency, status?1:0);

        if (status) {
            tCount++;
            tLatency += latency;
        }
        nTransactions++;

        gettimeofday(&t1, NULL);
        if ( ((t1.tv_sec-t0.tv_sec)*1000000 + (t1.tv_usec-t0.tv_usec)) > duration*1000000) 
            break;
    }

    printf("# Commit_Ratio: %lf\n", (double)tCount/nTransactions);
    printf("# Overall_Latency: %lf\n", tLatency/tCount);
    printf("# Begin: %d, %lf\n", beginCount, beginLatency/beginCount);
    printf("# Get: %d, %lf\n", getCount, getLatency/getCount);
    printf("# Put: %d, %lf\n", putCount, putLatency/putCount);
    printf("# Commit: %d, %lf\n", commitCount, commitLatency/commitCount);
    printf("Throughput: %lf\n", (double)tCount/duration);
}

int
main(int argc, char **argv)
{


    int opt;
    while ((opt = getopt(argc, argv, "c:d:N:l:w:k:f:m:e:s:")) != -1) {
        switch (opt) {
        case 'c': // Configuration path
        { 
            configPath = optarg;
            break;
        }

        case 'f': // Generated keys path
        { 
            keysPath = optarg;
            break;
        }

        case 'N': // Number of shards.
        { 
            char *strtolPtr;
            nShards = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') ||
                (nShards <= 0)) {
                fprintf(stderr, "option -n requires a numeric arg\n");
            }
            break;
        }

        case 'd': // Duration in seconds to run.
        { 
            char *strtolPtr;
            duration = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') ||
                (duration <= 0)) {
                fprintf(stderr, "option -n requires a numeric arg\n");
            }
            break;
        }

        case 'l': // Length of each transaction (deterministic!)
        {
            char *strtolPtr;
            tLen = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') ||
                (tLen <= 0)) {
                fprintf(stderr, "option -l requires a numeric arg\n");
            }
            break;
        }

        case 'w': // Percentage of writes (out of 100)
        {
            char *strtolPtr;
            wPer = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') ||
                (wPer < 0 || wPer > 100)) {
                fprintf(stderr, "option -w requires a arg b/w 0-100\n");
            }
            break;
        }

        case 'k': // Number of keys to operate on.
        {
            char *strtolPtr;
            nKeys = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') ||
                (nKeys <= 0)) {
                fprintf(stderr, "option -k requires a numeric arg\n");
            }
            break;
        }
        case 's':
        {
            char *strtolPtr;
            skew = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') || (skew < 0))
            {
                fprintf(stderr,
                        "option -s requires a numeric arg\n");
            }
            break;
        }
        case 'e':
        {
            char *strtolPtr;
            error = strtoul(optarg, &strtolPtr, 10);
            if ((*optarg == '\0') || (*strtolPtr != '\0') || (error < 0))
            {
                fprintf(stderr,
                        "option -e requires a numeric arg\n");
            }
            break;
        }

        case 'm': // Mode to run in [spec/vr/...]
        {
            if (strcasecmp(optarg, "spec-l") == 0) {
                mode = nistore::PROTO_SPEC;
            } else if (strcasecmp(optarg, "spec-occ") == 0) {
                mode = nistore::PROTO_SPEC;
            } else if (strcasecmp(optarg, "vr-l") == 0) {
                mode = nistore::PROTO_VR;
            } else if (strcasecmp(optarg, "vr-occ") == 0) {
                mode = nistore::PROTO_VR;
            } else if (strcasecmp(optarg, "fast-occ") == 0) {
                mode = nistore::PROTO_FAST;
            } else {
                fprintf(stderr, "unknown mode '%s'\n", optarg);
            }
            break;
        }

        default:
            fprintf(stderr, "Unknown argument %s\n", argv[optind]);
        }
    }

    if (mode == nistore::PROTO_UNKNOWN) {
        fprintf(stderr, "option -m is required\n");
        exit(0);
    }

    // Read in the keys from a file and populate the key-value store.
    ifstream in;
    in.open(keysPath);
    if (!in) {
        fprintf(stderr, "Could not read keys from: %s\n", keysPath);
        exit(0);
    }
    for (int i = 0; i < nKeys; i++) {
        getline(in, key);
        keys.push_back(key);
    }
    in.close();

    epoch(1);
    
    exit(0);
    return 0;
}


int rand_key() {
    // Zipf-like selection of keys.
    if (!ready) {
        zipf = new double[nKeys];

        double c = 0.0;
        for (int i = 1; i <= nKeys; i++) {
            c = c + (1.0 / pow((double) i, alpha));
        }
        c = 1.0 / c;

        double sum = 0.0;
        for (int i = 1; i <= nKeys; i++) {
            sum += (c / pow((double) i, alpha));
            zipf[i-1] = sum;
        }
        ready = true;
    }

    double random = 0.0;
    while (random == 0.0 || random == 1.0) {
        random = (1.0 + rand())/RAND_MAX;
    }

    // binary search to find key;
    int l = 0, r = nKeys, mid;
    while (l < r) {
        mid = (l + r) / 2;
        if (random > zipf[mid]) {
            l = mid + 1;
        } else if (random < zipf[mid]) {
            r = mid - 1;
        } else {
            break;
        }
    }
    return mid;
}