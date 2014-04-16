/*
 *  FREEWARE 
 *  Courtesy Scott Weston, 2014
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define MAX_PATH    1024

int detab(int tabsize, char *file)
{
    struct stat st;
    if(stat(file, &st) != 0) {
        printf("%s - not found\n", file);
        return -1;
    }
    if(!S_ISREG(st.st_mode)) {
        printf("%s - not a regular file\n", file);
        return -1;
    }
    FILE *fp = fopen(file, "rb");
    if(fp == NULL) {
        printf("%s - access denied\n", file);
        return -1;
    }

    char tmpfile1[1024];
    snprintf(tmpfile1, sizeof(tmpfile1), "%s.tmp1-%u", file, time(NULL));
    FILE *fpn = fopen(tmpfile1, "wb");
    if(fpn == NULL) {
        printf("%s - unable to create temporary file\n", tmpfile1);
        fclose(fp);
        return -1;
    }

    int p = 0;
    while(!feof(fp) && !ferror(fp)) {
        int c = fgetc(fp);
        if(c < 0)
            break;
        if(c == '\n' || c == '\r')
            p = 0;  
        else
        if(c == '\t') {
            int u = p + (tabsize - p % tabsize);
            while(p < u) {
                fputc(' ', fpn);
                p++;
            }
            continue;
        }
        else
            p++;

        fputc(c, fpn);
    }

    fclose(fp);
    fclose(fpn);

    char tmpfile2[1024];
    snprintf(tmpfile2, sizeof(tmpfile2), "%s.tmp2-%u", file, time(NULL));

    int error = 0;
    if(rename(file, tmpfile2) != 0)
        error++;
    if(!error && rename(tmpfile1, file) != 0)
        error++;
    unlink(tmpfile2);
    if(error > 0) {
        printf("%s - failed to change in-place\n", file);
        return -1;
    }

    printf("%s - ok\n", file);

    return 0;
}

int main(int argc, char **argv)
{
    int i, tabsize;
    if(argc < 3) {
        printf("usage: detab <tabsize> <files...>\n");
        return -1;
    }
    if((tabsize = atoi(argv[1])) < 1) {
        printf("tabsize must be greater than 0\n");
        return -2;
    }
    for(i = 2; i < argc; i++)
        detab(tabsize, argv[i]);
    return 0;
}
