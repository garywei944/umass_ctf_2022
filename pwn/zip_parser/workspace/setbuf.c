#include <stdio.h>

char outbuf[BUFSIZ];

int main(void)

{
  setbuf(stdout, outbuf);  // 把缓冲区与流相连

  puts("This is a test of buffered output.\n");

  puts(outbuf);

  fflush(stdout);  // 刷新

  puts(outbuf);  // 输出

  return 0;
}
