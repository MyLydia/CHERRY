#include<stdio.h>
#include<time.h>
#include<stdlib.h>


int get_char(){
    int model;
    int sign;
    model = rand()%2;
    if(model == 0){
        
        sign = rand()%10;
        sign = sign + 48;
        
    }else{
        
        sign = rand()%26;
        sign = sign + 97;
    }
    return sign;
}

int main(){
    
		char pwd[8];
		int i;
		srand((unsigned)time(NULL));
		for(int i = 0;i < 8;i++){
				pwd[i] = get_char();
		}
		printf("%s\n",pwd);
    return 0;
}

