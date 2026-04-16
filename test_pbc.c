#include <pbc/pbc.h>
#include <stdio.h>

int main() {
    char param_str[] = "type a\n"
"q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
"h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
"r 730750818665451621361119245571504901405976559617\n"
"exp2 159\n"
"exp1 107\n"
"sign1 1\n"
"sign0 1\n";
    pairing_t pairing;
    element_t g1, g2, gt;
    pairing_init_set_str(pairing, param_str);
    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_GT(gt, pairing);
    
    element_random(g1);
    element_random(g2);
    
    pairing_apply(gt, g1, g2, pairing);
    
    printf("Pairing computation successful!\n");
    return 0;
}
