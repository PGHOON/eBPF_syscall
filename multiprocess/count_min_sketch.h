#ifndef COUNT_MIN_SKETCH_H
#define COUNT_MIN_SKETCH_H

#define CMS_WIDTH 1024
#define CMS_DEPTH 4

struct CountMinSketch {
    unsigned int width;
    unsigned int depth;
    unsigned int table[CMS_DEPTH][CMS_WIDTH];
};

static __inline int update_count_min_sketch(struct CountMinSketch *cms, unsigned int key) {
    unsigned int min_count = -1;

    for (int i = 0; i < CMS_DEPTH; ++i) {
        unsigned int hash = (key + i) % CMS_WIDTH;
        cms->table[i][hash]++;
        if (cms->table[i][hash] < min_count) {
            min_count = cms->table[i][hash];
        }
    }
    return min_count;
}

#endif /* COUNT_MIN_SKETCH_H */
