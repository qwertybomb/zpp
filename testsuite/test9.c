#define M 0

#if 0
123
#endif

#if M
123
#endif

#if M + 1
#if M + (1 + 2*3)
#if !!M
#if !!!!M
#if !!!!M
#if !!!!M
#endif
#endif
#endif
#endif
90
#endif
80
#endif

#if 1 + 2*3/2*2 - 6
1
#endif

#if ((1 + 2))*3/2*2 - 6
1
#endif

#if (1 + 2)*3/2*2 - 6
1
#endif

#if ~2 + 1 - -2 + 1
123
#endif

#if !((1 << 4) - 16)
567
#endif

#if !((16 >> 4) - 1)
568
#endif

#if !((1 << -2+7) - 32)
569
#endif

#if !((32 >> 2+3) - 1)
570
#endif

#if (1 + 2*3 - 1) != 7
126
#endif

#if (1 + 2*3 - 1) > 7
127
#else
458
#endif

#if (1 + 2*3 - 1) < 7
128
#else
459
#endif

#if (1 + 2*3 - 1) >= 7
129
#else
460
#endif

#if (1 + 2*3 - 1) >= 7
1230
#elif 1
4609
#endif

#if (1 + 2*3 - 1) >= 7
#elif 5 + 7 - 12
1280
#elif 1 + 2 < 5
4602
#else
890
#endif

#if (1 + 2*3 - 1) >= 7
#elif 5 + 7 - 12
1280
#elif 1 + 2 >= 5
4602
#else
890
#endif

#if 1 + 2*3 != 7 ? 0 : 1
567
#endif

#if 1 + 2*3 != 7 ? 1 : 0
568
#endif

#if 1 + 2*3 != 7 ? 1 : 1 + 2 == 3 ? 4 : 0
569
#endif

#if 1 + 2*3 != 7 ? 1 : 1 + 2 == 3 ? 0 : 4
570
#endif

#if 1 < 0 ? 1/0 : 1
908
#endif

#if 0x12 == 18 ? (1 | 2) == 3 : 0
909
#endif

#if 0x14 != 20 ? 1/0x00 : 0x001&0x001
910
#endif

#if 0x14 != 20 ? 1/0x00 : 0x101^0x001
911
#endif

#if 0x14 != 20 ? 1 : 0x100^0x100
912
#else
913
#endif

#if 0x12345678 == 305419897
9
#else
8
#endif

#if 1==1
#if 1==0
#elif 1==1
2
#elif 1
#endif

#if 1==0
#elif 1==1
2
#endif
#endif

#if 1*3*3*(2-1u) > -1 ? 1 : 0
89
#endif

#if 1 > -1 ? 1 : 0
88
#endif

#if 1U+1UL+1ULL+1Ull+1Ul+1u+1ul+1ull+1uLL+1uL+1l+1ll+1L+1LL
56
#endif

#if 0128 == 88
67
#endif
