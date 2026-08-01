/*
 * IDA-MCP complex fixture program.
 *
 * This file is intentionally written as a stable reverse-engineering test
 * fixture.  Tests should locate objects through MCP-returned names, sentinel
 * strings, xrefs, and metadata from the compiled binary instead of hard-coded
 * addresses.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#define IDA_MCP_NOINLINE __declspec(noinline)
#else
#define IDA_MCP_NOINLINE __attribute__((noinline))
#endif

typedef enum IdaMcpStatus {
    IDA_MCP_STATUS_OK = 0,
    IDA_MCP_STATUS_INVALID = 1,
    IDA_MCP_STATUS_NOT_FOUND = 2,
    IDA_MCP_STATUS_OVERFLOW = 3,
} IdaMcpStatus;

typedef struct IdaMcpPoint {
    int32_t x;
    int32_t y;
} IdaMcpPoint;

typedef struct IdaMcpRect {
    IdaMcpPoint top_left;
    IdaMcpPoint bottom_right;
    uint32_t color;
    char name[32];
} IdaMcpRect;

typedef struct IdaMcpNode {
    int32_t id;
    int32_t value;
    struct IdaMcpNode *next;
    struct IdaMcpNode *prev;
} IdaMcpNode;

typedef struct IdaMcpList {
    IdaMcpNode *head;
    IdaMcpNode *tail;
    int32_t count;
} IdaMcpList;

typedef union IdaMcpPayload {
    uint64_t raw;
    double scalar;
    char text[8];
} IdaMcpPayload;

typedef struct IdaMcpRecord {
    uint32_t magic;
    IdaMcpStatus status;
    IdaMcpRect bounds;
    IdaMcpPayload payload;
    int32_t scores[8];
} IdaMcpRecord;

typedef int32_t (*IdaMcpBinaryOp)(int32_t lhs, int32_t rhs);
typedef void (*IdaMcpVisitCallback)(void *ctx, const IdaMcpRecord *record);

const char *ida_mcp_sentinel_entry = "IDA_MCP_COMPLEX_SENTINEL_ENTRY";
const char *ida_mcp_sentinel_strings[] = {
    "IDA_MCP_COMPLEX_SENTINEL_RECT",
    "IDA_MCP_COMPLEX_SENTINEL_LIST",
    "IDA_MCP_COMPLEX_SENTINEL_STACK",
    "IDA_MCP_COMPLEX_SENTINEL_CALLBACK",
    "IDA_MCP_COMPLEX_SENTINEL_PATCH_TARGET",
};

volatile int32_t ida_mcp_global_counter = 7;
volatile uint8_t ida_mcp_patch_bytes[16] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
};
IdaMcpRecord ida_mcp_global_records[3];
IdaMcpList ida_mcp_global_list = {0};

static volatile int32_t ida_mcp_sink = 0;

IDA_MCP_NOINLINE IdaMcpPoint ida_mcp_point_make(int32_t x, int32_t y) {
    IdaMcpPoint point;
    point.x = x;
    point.y = y;
    return point;
}

IDA_MCP_NOINLINE int32_t ida_mcp_point_distance_squared(
    const IdaMcpPoint *lhs,
    const IdaMcpPoint *rhs
) {
    int32_t dx = lhs->x - rhs->x;
    int32_t dy = lhs->y - rhs->y;
    return dx * dx + dy * dy;
}

IDA_MCP_NOINLINE IdaMcpStatus ida_mcp_rect_init(
    IdaMcpRect *rect,
    int32_t x1,
    int32_t y1,
    int32_t x2,
    int32_t y2,
    uint32_t color,
    const char *name
) {
    if (rect == NULL || name == NULL) {
        return IDA_MCP_STATUS_INVALID;
    }
    if (x2 < x1 || y2 < y1) {
        return IDA_MCP_STATUS_INVALID;
    }

    rect->top_left = ida_mcp_point_make(x1, y1);
    rect->bottom_right = ida_mcp_point_make(x2, y2);
    rect->color = color;
    strncpy(rect->name, name, sizeof(rect->name) - 1);
    rect->name[sizeof(rect->name) - 1] = '\0';
    return IDA_MCP_STATUS_OK;
}

IDA_MCP_NOINLINE int32_t ida_mcp_rect_width(const IdaMcpRect *rect) {
    return rect->bottom_right.x - rect->top_left.x;
}

IDA_MCP_NOINLINE int32_t ida_mcp_rect_height(const IdaMcpRect *rect) {
    return rect->bottom_right.y - rect->top_left.y;
}

IDA_MCP_NOINLINE int32_t ida_mcp_rect_area(const IdaMcpRect *rect) {
    return ida_mcp_rect_width(rect) * ida_mcp_rect_height(rect);
}

IDA_MCP_NOINLINE int32_t ida_mcp_rect_contains(
    const IdaMcpRect *rect,
    const IdaMcpPoint *point
) {
    return point->x >= rect->top_left.x &&
           point->x <= rect->bottom_right.x &&
           point->y >= rect->top_left.y &&
           point->y <= rect->bottom_right.y;
}

IDA_MCP_NOINLINE IdaMcpNode *ida_mcp_node_create(int32_t id, int32_t value) {
    IdaMcpNode *node = (IdaMcpNode *)malloc(sizeof(IdaMcpNode));
    if (node == NULL) {
        return NULL;
    }
    node->id = id;
    node->value = value;
    node->next = NULL;
    node->prev = NULL;
    return node;
}

IDA_MCP_NOINLINE IdaMcpStatus ida_mcp_list_push_back(
    IdaMcpList *list,
    int32_t id,
    int32_t value
) {
    IdaMcpNode *node = ida_mcp_node_create(id, value);
    if (node == NULL) {
        return IDA_MCP_STATUS_OVERFLOW;
    }

    if (list->tail != NULL) {
        list->tail->next = node;
        node->prev = list->tail;
        list->tail = node;
    } else {
        list->head = node;
        list->tail = node;
    }
    list->count++;
    return IDA_MCP_STATUS_OK;
}

IDA_MCP_NOINLINE IdaMcpNode *ida_mcp_list_find(IdaMcpList *list, int32_t id) {
    IdaMcpNode *cursor = list->head;
    while (cursor != NULL) {
        if (cursor->id == id) {
            return cursor;
        }
        cursor = cursor->next;
    }
    return NULL;
}

IDA_MCP_NOINLINE int32_t ida_mcp_list_sum(const IdaMcpList *list) {
    int32_t sum = 0;
    const IdaMcpNode *cursor = list->head;
    while (cursor != NULL) {
        sum += cursor->value;
        cursor = cursor->next;
    }
    return sum;
}

IDA_MCP_NOINLINE void ida_mcp_list_clear(IdaMcpList *list) {
    IdaMcpNode *cursor = list->head;
    while (cursor != NULL) {
        IdaMcpNode *next = cursor->next;
        free(cursor);
        cursor = next;
    }
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
}

IDA_MCP_NOINLINE int32_t ida_mcp_op_add(int32_t lhs, int32_t rhs) {
    return lhs + rhs;
}

IDA_MCP_NOINLINE int32_t ida_mcp_op_sub(int32_t lhs, int32_t rhs) {
    return lhs - rhs;
}

IDA_MCP_NOINLINE int32_t ida_mcp_op_mul(int32_t lhs, int32_t rhs) {
    return lhs * rhs;
}

IDA_MCP_NOINLINE int32_t ida_mcp_op_div(int32_t lhs, int32_t rhs) {
    if (rhs == 0) {
        return 0;
    }
    return lhs / rhs;
}

IdaMcpBinaryOp ida_mcp_operations[4] = {
    ida_mcp_op_add,
    ida_mcp_op_sub,
    ida_mcp_op_mul,
    ida_mcp_op_div,
};

IDA_MCP_NOINLINE int32_t ida_mcp_apply_operation(
    int32_t op_index,
    int32_t lhs,
    int32_t rhs
) {
    if (op_index < 0 || op_index >= 4) {
        return -1;
    }
    return ida_mcp_operations[op_index](lhs, rhs);
}

IDA_MCP_NOINLINE int32_t ida_mcp_recursive_factorial(int32_t value) {
    if (value <= 1) {
        return 1;
    }
    return value * ida_mcp_recursive_factorial(value - 1);
}

IDA_MCP_NOINLINE void ida_mcp_record_visit_sum(
    void *ctx,
    const IdaMcpRecord *record
) {
    int32_t *sum = (int32_t *)ctx;
    for (int32_t i = 0; i < 8; i++) {
        *sum += record->scores[i];
    }
}

IDA_MCP_NOINLINE int32_t ida_mcp_visit_records(
    IdaMcpRecord *records,
    int32_t count,
    IdaMcpVisitCallback callback,
    void *ctx
) {
    if (records == NULL || callback == NULL || count < 0) {
        return IDA_MCP_STATUS_INVALID;
    }

    for (int32_t i = 0; i < count; i++) {
        callback(ctx, &records[i]);
    }
    return IDA_MCP_STATUS_OK;
}

IDA_MCP_NOINLINE int32_t ida_mcp_stack_heavy_transform(
    const int32_t *input,
    int32_t count,
    const char *label
) {
    struct IdaMcpStackFrameFixture {
        char label_copy[64];
        int32_t sorted[16];
        int32_t histogram[8];
        IdaMcpRecord local_record;
        double scale;
    } frame;

    memset(&frame, 0, sizeof(frame));
    strncpy(frame.label_copy, label, sizeof(frame.label_copy) - 1);
    frame.scale = 2.5;
    frame.local_record.magic = 0x4d435049u;
    frame.local_record.status = IDA_MCP_STATUS_OK;
    ida_mcp_rect_init(
        &frame.local_record.bounds,
        3,
        5,
        42,
        55,
        0x00ff8040u,
        "IDA_MCP_STACK_RECT"
    );

    int32_t limit = count < 16 ? count : 16;
    int32_t total = 0;
    for (int32_t i = 0; i < limit; i++) {
        int32_t value = input[i];
        frame.sorted[i] = value;
        frame.histogram[value & 7]++;
        frame.local_record.scores[i & 7] += value;
        total += value;
    }

    for (int32_t i = 0; i < limit; i++) {
        for (int32_t j = i + 1; j < limit; j++) {
            if (frame.sorted[j] < frame.sorted[i]) {
                int32_t tmp = frame.sorted[i];
                frame.sorted[i] = frame.sorted[j];
                frame.sorted[j] = tmp;
            }
        }
    }

    printf("%s: %s total=%d scale=%.1f\n",
           ida_mcp_sentinel_strings[2],
           frame.label_copy,
           total,
           frame.scale);
    return total + frame.histogram[0] + frame.local_record.bounds.color;
}

IDA_MCP_NOINLINE int32_t ida_mcp_patch_target(int32_t value) {
    ida_mcp_global_counter += value;
    return ida_mcp_global_counter ^ ida_mcp_patch_bytes[value & 15];
}

IDA_MCP_NOINLINE void ida_mcp_init_records(void) {
    memset(ida_mcp_global_records, 0, sizeof(ida_mcp_global_records));
    for (int32_t i = 0; i < 3; i++) {
        IdaMcpRecord *record = &ida_mcp_global_records[i];
        record->magic = 0x49444130u + (uint32_t)i;
        record->status = IDA_MCP_STATUS_OK;
        record->payload.raw = 0x1122334455667700ull + (uint64_t)i;
        ida_mcp_rect_init(
            &record->bounds,
            i * 10,
            i * 20,
            i * 10 + 100,
            i * 20 + 50,
            0x00aa0000u + (uint32_t)i,
            ida_mcp_sentinel_strings[0]
        );
        for (int32_t j = 0; j < 8; j++) {
            record->scores[j] = (i + 1) * (j + 3);
        }
    }
}

IDA_MCP_NOINLINE int32_t ida_mcp_complex_dispatch(int32_t seed) {
    int32_t values[10] = {13, 7, 29, 3, 17, 11, 5, 23, 19, 31};
    int32_t callback_sum = 0;

    ida_mcp_init_records();
    ida_mcp_list_push_back(&ida_mcp_global_list, 100, seed + 10);
    ida_mcp_list_push_back(&ida_mcp_global_list, 200, seed + 20);
    ida_mcp_list_push_back(&ida_mcp_global_list, 300, seed + 30);

    IdaMcpNode *found = ida_mcp_list_find(&ida_mcp_global_list, 200);
    int32_t list_value = found != NULL ? found->value : -1000;
    int32_t op_value = ida_mcp_apply_operation(seed & 3, list_value, 7);
    int32_t stack_value = ida_mcp_stack_heavy_transform(
        values,
        10,
        "IDA_MCP_STACK_LABEL"
    );

    ida_mcp_visit_records(
        ida_mcp_global_records,
        3,
        ida_mcp_record_visit_sum,
        &callback_sum
    );

    printf("%s seed=%d list=%d op=%d callback=%d patch=%d\n",
           ida_mcp_sentinel_entry,
           seed,
           ida_mcp_list_sum(&ida_mcp_global_list),
           op_value,
           callback_sum,
           ida_mcp_patch_target(seed));

    ida_mcp_list_clear(&ida_mcp_global_list);
    return op_value + stack_value + callback_sum + ida_mcp_recursive_factorial(5);
}

int main(int argc, char **argv) {
    int32_t seed = 9;
    if (argc > 1) {
        seed = atoi(argv[1]);
    }

    puts("IDA_MCP_COMPLEX_SENTINEL_MAIN_BEGIN");
    ida_mcp_sink = ida_mcp_complex_dispatch(seed);
    printf("IDA_MCP_COMPLEX_SENTINEL_MAIN_END result=%d\n", ida_mcp_sink);
    return (int)(ida_mcp_sink & 0xff);
}
