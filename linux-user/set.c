#include "set.h"

int insert(set_t *s, int t)
{
	for (int i = 0; i < s->size; i++)
	{
		if (s->element[i] == t)
		{
			return i;
		}
	}
	s->element[s->size++] = t;
	return s->size;
}

void clear(set_t *s)
{
	s->size = 0;
}

int find(set_t *s, int n)
{
	for (int i = 0; i < s->size; i++)
	{
		if (s->element[i] == n)
		{
			return i;
		}
	}
	return -1;
}