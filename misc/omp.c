#include <omp.h>
int main(int argc, char* argv[]){
    int i=0;
    #pragma omp parallel
    {
        i+=1;
    }
    return i;
}
