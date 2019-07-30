#ifndef SET_H
#define SET_H



struct set
{
	int element[100];
	int size;
};


typedef struct set set_t;


int insert(set_t *s, int t);

void clear(set_t *s);


#endif 
