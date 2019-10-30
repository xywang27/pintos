#ifndef THREADS_FIXEDNUMBER_H
#define THREADS_FIXEDNUMBER_H

#define Q 14

#define F (1 << Q)

#define CONVERT(A) (A*F)

#define ADD(A, B) (A + B)

#define SUB(A, B) (A - B)

#define ADDFIXED(A, B) (A + (B*F))

#define SUBFIXED(A, B) (A - (B*F))

#define MUX(A, B) (((int64_t)A) * B / F)

#define MUXFIXED(A, B) (A * B)

#define DIV(A, B) (((int64_t)A) * F / B)

#define DIVFIXED(A, B) (A / B)

#define CONVERTTOINT_ZERO(A) (A/F)

#define CONVERTTOINT_NER(A) (A >= 0 ? ((A + F / 2) / F) : ((A - F / 2) / F))

#endif
