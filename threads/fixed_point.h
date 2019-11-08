#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H

#define F (1 << 14)
/*Convert n to fixed point*/
#define CONVERT_INT_TO_FP(N) (N * F)

/*Convert x to integer (rounding toward zero)*/
#define CONVERT_FP_TO_INT_ZERO(X) (X / F)

/*Convert x to integer (rounding to nearest)*/
#define CONVERT_FP_TO_INT_NEAREST(X) (X >= 0 ? ((X + F / 2) / F) : ((X - F / 2) / F))

/*Add x and y*/
#define ADD(X,Y) (X + Y)

/*Subtract y from x*/
#define SUB(X,Y) (X - Y)

/*Add x and n*/
#define ADD_INT(X,N) (X + (N * F))

/*Subtract n from x*/
#define SUB_INT(X,N) (X - (N * F))

/*Multiply x by y*/
#define MUL(X,Y) (((int64_t) X) * Y / F)

/*Multiply x by n*/
#define MUL_INT(X,N) (X * N)

/*Divide x by y*/
#define DIV(X,Y) (((int64_t) X) * F / Y)

/*Divide x by n*/
#define DIV_INT(X,N) (X / N)

#endif /* thread/fixed_point.h */
