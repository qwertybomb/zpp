
#define SQ(x) (x)*(x)

#define M0(x,y) SQ(x)+SQ(y)<4?0:0xe0
#define M1(x,y,x0,y0) (SQ(x)+SQ(y)<4)?M0(SQ(x)-SQ(y)+(x0),2*(x)*(y)+(y0)):0xc0
#define M2(x,y,x0,y0) (SQ(x)+SQ(y)<4)?M1(SQ(x)-SQ(y)+(x0),2*(x)*(y)+(y0),x0,y0):0xa0
#define M3(x,y,x0,y0) (SQ(x)+SQ(y)<4)?M2(SQ(x)-SQ(y)+(x0),2*(x)*(y)+(y0),x0,y0):0x80
#define M4(x,y,x0,y0) (SQ(x)+SQ(y)<4)?M3(SQ(x)-SQ(y)+(x0),2*(x)*(y)+(y0),x0,y0):0x60
#define M5(x,y,x0,y0) (SQ(x)+SQ(y)<4)?M4(SQ(x)-SQ(y)+(x0),2*(x)*(y)+(y0),x0,y0):0x40
#define M6(x,y,x0,y0) (SQ(x)+SQ(y)<4)?M5(SQ(x)-SQ(y)+(x0),2*(x)*(y)+(y0),x0,y0):0x20

#define XF(x) (x)/20-2.2
#define YF(y) (y)/20-1.6

#define C1(x,y) M3(XF(x), YF(y), XF(x), YF(y)),
//               ^- change this to 5 or 6 to increase detail

#define C2(x,y) C1(x,y) C1(x+1,y)
#define C4(x,y) C2(x,y) C2(x+2,y)
#define C8(x,y) C4(x,y) C4(x+4,y)
#define C16(x,y) C8(x,y) C8(x+8,y)
#define C32(x,y) C16(x,y) C16(x+16,y)
#define C64(x,y) C32(x,y) C32(x+32,y)

#define R2(y) C64(0.0,y) C64(0.0,y+1)
#define R4(y) R2(y) R2(y+2)
#define R8(y) R4(y) R4(y+4)
#define R16(y) R8(y) R8(y+8)
#define R32(y) R16(y) R16(y+16)
#define R64(y) R32(y) R32(y+32)

static const unsigned char pixels[] = {
	R64(0.0)
};

int main() {
	fputs("P5\n64 64\n255\n", stdout);
	fwrite(pixels, sizeof(pixels), 1, stdout);
	return 0;
}
