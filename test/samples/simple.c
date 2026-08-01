/**
 * IDA-MCP 简单测试程序
 *
 * 用途：测试基本的 IDA 分析功能
 * - 函数列表、反汇编、反编译
 * - 字符串识别
 * - 全局变量
 * - 交叉引用
 */

#include <stdio.h>
#include <string.h>

// 全局变量
int g_counter = 0;
const char *g_app_name = "IDA-MCP Test";
char g_buffer[256] = {0};

// 简单的辅助函数
int add_numbers(int a, int b) { return a + b; }

int multiply_numbers(int a, int b) { return a * b; }

// 使用全局变量的函数
void increment_counter(void) { g_counter++; }

int get_counter(void) { return g_counter; }

// 字符串处理函数
void print_message(const char *msg) { printf("[%s] %s\n", g_app_name, msg); }

void copy_to_buffer(const char *src) {
  strncpy(g_buffer, src, sizeof(g_buffer) - 1);
  g_buffer[sizeof(g_buffer) - 1] = '\0';
}

// 带条件分支的函数
int calculate(int op, int a, int b) {
  switch (op) {
  case 0:
    return add_numbers(a, b);
  case 1:
    return multiply_numbers(a, b);
  case 2:
    return a - b;
  case 3:
    if (b != 0)
      return a / b;
    return 0;
  default:
    return -1;
  }
}

// 带循环的函数
int sum_range(int start, int end) {
  int sum = 0;
  for (int i = start; i <= end; i++) {
    sum = add_numbers(sum, i);
    increment_counter();
  }
  return sum;
}

// 递归函数
int factorial(int n) {
  if (n <= 1)
    return 1;
  return n * factorial(n - 1);
}

// main 函数
int main(int argc, char *argv[]) {
  print_message("Starting test program");

  // 测试基本运算
  int result = calculate(0, 10, 20);
  printf("10 + 20 = %d\n", result);

  result = calculate(1, 5, 6);
  printf("5 * 6 = %d\n", result);

  // 测试循环
  result = sum_range(1, 10);
  printf("Sum 1-10 = %d, counter = %d\n", result, get_counter());

  // 测试递归
  result = factorial(5);
  printf("5! = %d\n", result);

  // 测试字符串
  if (argc > 1) {
    copy_to_buffer(argv[1]);
    print_message(g_buffer);
  }

  print_message("Test completed");
  return 0;
}
