hdr[95] = 0x35
buf = hdr

init:
init = 0x35 >> 2 = 0xD & 0xF = 0xD + 1 = 0xE = 14

for loop:
index = 93 / init * init = 84; index >= init = 14; index -= init = 14 (84, 70, 56, 32, 18)

for body:
tmp = buf[index];
buf[index] = buf[index + 1];
buf[index + 1] = tmp;

end:
hdr[0] = buf[0] >> 2 | buf[95] << 6

for loop:
i = 1; i < 96; ++i
for body:
hdr[i] = buf[i] >> 2 | buf[i - 1] << 6;

1F 03 19 37 B0 84

hdr[0] = 0x1F >> 2 | 0x84 << 6 =  0x7 | 0x0 = 0x7
hdr[1] = 0x03 >> 2 | 0x7 << 6 = 
hdr[2] =
hdr[3] = 
hdr[4] =
hdr[5] =
