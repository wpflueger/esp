#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdbool.h>

/*****************************************************************************/

// These constants are used to distinguish the different types of
// tests from the NIST Cryptographic Algorithm Validation Program.

/* ECB_OPERATION_MODE */
/* cavp_data.k --> key   */
/* cavp_data.p --> plaintext */
/* cavp_data.c --> ciphertext */

/* CBC_OPERATION_MODE */
/* cavp_data.k --> key   */
/* cavp_data.p --> plaintext */
/* cavp_data.c --> ciphertext */
/* cavp_data.i --> init vectr. */

/* GCM_OPERATION_MODE */
/* cavp_data.k --> key   */
/* cavp_data.p --> plaintext */
/* cavp_data.c --> ciphertext */
/* cavp_data.i --> init vectr. */
/* cavp_data.t --> auth. tag */
/* cavp_data.a --> aad data */
/* cavp_data.f --> test fail? */

typedef struct {

    /* Total number of tests */
    unsigned tot_tests;

    /* Number of encryptions */
    unsigned enc_tests;

    /* Keys */
    uint8_t **k;
    uint32_t *lk;

    /* Plaintexts */
    uint8_t **p;
    uint32_t *lp;

    /* Ciphertexts */
    uint8_t **c;
    uint32_t *lc;

    /* Init vector */
    uint8_t **i;
    uint32_t *li;

    /* Auth. Tag */
    uint8_t **t;
    uint32_t *lt;

    /* AAD data */
    uint8_t **a;
    uint32_t *la;

    /* Fails */
    bool *f;

} cavp_data;

void parse_cavp(cavp_data *cavp, const char *filename, int sel)
{
    char buf[3];
    char *token;
    size_t len = 0;
    unsigned i, j = 0;
    char *line = NULL;

    FILE *file = fopen(filename, "r");

    if (file == NULL)
        fprintf(stderr, "Error: %s cannot be open\n", filename);

    cavp->k = NULL;
    cavp->i = NULL;
    cavp->p = NULL;
    cavp->c = NULL;
    cavp->t = NULL;
    cavp->a = NULL;
    cavp->f = NULL;
    cavp->lk = NULL;
    cavp->li = NULL;
    cavp->lp = NULL;
    cavp->lc = NULL;
    cavp->lt = NULL;
    cavp->la = NULL;
    cavp->tot_tests = 0;

    if (sel == ECB_OPERATION_MODE)
    {
        while (getline(&line, &len, file) != -1)
        {
            if (strstr(line, "[DECRYPT]"))
            {
                cavp->enc_tests = cavp->tot_tests;
            }

            if (strstr(line, "KEY"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->tot_tests += 1;
                cavp->k = (uint8_t**) realloc(cavp->k, cavp->tot_tests * sizeof(uint8_t*));
                cavp->p = (uint8_t**) realloc(cavp->p, cavp->tot_tests * sizeof(uint8_t*));
                cavp->c = (uint8_t**) realloc(cavp->c, cavp->tot_tests * sizeof(uint8_t*));
                cavp->lk = (uint32_t*) realloc(cavp->lk, cavp->tot_tests * sizeof(uint32_t));
                cavp->lp = (uint32_t*) realloc(cavp->lp, cavp->tot_tests * sizeof(uint32_t));
                cavp->lc = (uint32_t*) realloc(cavp->lc, cavp->tot_tests * sizeof(uint32_t));

                cavp->k[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lk[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->k)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "PLAINTEXT"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->p[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lp[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->p)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "CIPHERTEXT"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->c[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lc[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->c)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }

            free(line);
            line = NULL;
            len = 0;
        }
    }
    else if (sel == CBC_OPERATION_MODE)
             /* sel == OFB_OPERATION_MODE) */
    {
        while (getline(&line, &len, file) != -1)
        {
            if (strstr(line, "[DECRYPT]"))
            {
                cavp->enc_tests = cavp->tot_tests;
            }

            if (strstr(line, "KEY"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->tot_tests += 1;
                cavp->k = (uint8_t**) realloc(cavp->k, cavp->tot_tests * sizeof(uint8_t*));
                cavp->p = (uint8_t**) realloc(cavp->p, cavp->tot_tests * sizeof(uint8_t*));
                cavp->c = (uint8_t**) realloc(cavp->c, cavp->tot_tests * sizeof(uint8_t*));
                cavp->i = (uint8_t**) realloc(cavp->i, cavp->tot_tests * sizeof(uint8_t*));
                cavp->lk = (uint32_t*) realloc(cavp->lk, cavp->tot_tests * sizeof(uint32_t));
                cavp->lp = (uint32_t*) realloc(cavp->lp, cavp->tot_tests * sizeof(uint32_t));
                cavp->lc = (uint32_t*) realloc(cavp->lc, cavp->tot_tests * sizeof(uint32_t));
                cavp->li = (uint32_t*) realloc(cavp->li, cavp->tot_tests * sizeof(uint32_t));

                cavp->k[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lk[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->k)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "PLAINTEXT"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->p[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lp[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->p)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "CIPHERTEXT"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->c[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lc[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->c)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "IV ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->i[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->li[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->i)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }

            free(line);
            line = NULL;
            len = 0;
        }
    }
    else if (sel == GCM_OPERATION_MODE)
    {
        while (getline(&line, &len, file) != -1)
        {
            if (strstr(line, "Key ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->tot_tests += 1;
                cavp->f = (bool*) realloc(cavp->f, cavp->tot_tests * sizeof(bool));
                cavp->k = (uint8_t**) realloc(cavp->k, cavp->tot_tests * sizeof(uint8_t*));
                cavp->i = (uint8_t**) realloc(cavp->i, cavp->tot_tests * sizeof(uint8_t*));
                cavp->p = (uint8_t**) realloc(cavp->p, cavp->tot_tests * sizeof(uint8_t*));
                cavp->c = (uint8_t**) realloc(cavp->c, cavp->tot_tests * sizeof(uint8_t*));
                cavp->t = (uint8_t**) realloc(cavp->t, cavp->tot_tests * sizeof(uint8_t*));
                cavp->a = (uint8_t**) realloc(cavp->a, cavp->tot_tests * sizeof(uint8_t*));
                cavp->lk = (uint32_t*) realloc(cavp->lk, cavp->tot_tests * sizeof(uint32_t));
                cavp->li = (uint32_t*) realloc(cavp->li, cavp->tot_tests * sizeof(uint32_t));
                cavp->lp = (uint32_t*) realloc(cavp->lp, cavp->tot_tests * sizeof(uint32_t));
                cavp->lc = (uint32_t*) realloc(cavp->lc, cavp->tot_tests * sizeof(uint32_t));
                cavp->lt = (uint32_t*) realloc(cavp->lt, cavp->tot_tests * sizeof(uint32_t));
                cavp->la = (uint32_t*) realloc(cavp->la, cavp->tot_tests * sizeof(uint32_t));

                cavp->k[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lk[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->k)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "IV ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if (token == NULL || strlen(token) <= 2)
                {
                    cavp->i[cavp->tot_tests - 1] = NULL;
                    cavp->li[cavp->tot_tests - 1] = 0;
                }
                else
                {
                    cavp->i[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * (strlen(token) - 1) / 2);
                    cavp->li[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                    for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                    {
                        buf[0] = token[i + 0];
                        buf[1] = token[i + 1];
                        (cavp->i)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                    }
                }
            }
            else if (strstr(line, "PT ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->f[cavp->tot_tests - 1] = false;

                if (token == NULL || strlen(token) <= 2)
                {
                    cavp->p[cavp->tot_tests - 1] = NULL;
                    cavp->lp[cavp->tot_tests - 1] = 0;
                }
                else
                {
                    cavp->p[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * (strlen(token) - 1) / 2);
                    cavp->lp[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                    for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                    {
                        buf[0] = token[i + 0];
                        buf[1] = token[i + 1];
                        (cavp->p)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                    }
                }
            }
            else if (strstr(line, "AAD ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if (token == NULL || strlen(token) <= 2)
                {
                    cavp->a[cavp->tot_tests - 1] = NULL;
                    cavp->la[cavp->tot_tests - 1] = 0;
                }
                else
                {
                    cavp->a[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * (strlen(token) - 1) / 2);
                    cavp->la[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                    for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                    {
                        buf[0] = token[i + 0];
                        buf[1] = token[i + 1];
                        (cavp->a)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                    }
                }
            }
            else if (strstr(line, "CT ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if (token == NULL || strlen(token) <= 2)
                {
                    cavp->c[cavp->tot_tests - 1] = NULL;
                    cavp->lc[cavp->tot_tests - 1] = 0;
                }
                else
                {
                    cavp->c[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * (strlen(token) - 1) / 2);
                    cavp->lc[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                    for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                    {
                        buf[0] = token[i + 0];
                        buf[1] = token[i + 1];
                        (cavp->c)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                    }
                }
            }
            else if (strstr(line, "Tag ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if (token == NULL || strlen(token) <= 2)
                {
                    cavp->t[cavp->tot_tests - 1] = NULL;
                    cavp->lt[cavp->tot_tests - 1] = 0;
                }
                else
                {
                    cavp->t[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * (strlen(token) - 1) / 2);
                    cavp->lt[cavp->tot_tests - 1] = (strlen(token) - 1) / 2;

                    for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                    {
                        buf[0] = token[i + 0];
                        buf[1] = token[i + 1];
                        (cavp->t)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                    }
                }
            }
            else if (strstr(line, "FAIL"))
            {
                cavp->f[cavp->tot_tests - 1] = true;
                cavp->p[cavp->tot_tests - 1] = NULL;
                cavp->lp[cavp->tot_tests - 1] = 0;
            }

            free(line);
            line = NULL;
            len = 0;
        }
    }

    fclose(file);
    free(line);
}

int eval_cavp(cavp_data *cavp, uint8_t *buffer, uint8_t *buffer_t, int test,
        bool encryption, int returnv, int sel, bool verbose)
{
    unsigned k;
    bool correct = 1;

    if (sel == ECB_OPERATION_MODE ||
        sel == CBC_OPERATION_MODE)
    {
        if (encryption)
        {
            for (k = 0; k < cavp->lc[test]; ++k)
                if (buffer[k] != cavp->c[test][k])
                    correct = 0;
        }
        else
        {
            for (k = 0; k < cavp->lp[test]; ++k)
                if (buffer[k] != cavp->p[test][k])
                    correct = 0;
        }
    }
    else if (sel == GCM_OPERATION_MODE)
    {
        if (encryption)
        {
            for (k = 0; k < cavp->lc[test]; ++k)
                if (buffer[k] != cavp->c[test][k])
                    correct = 0;

            for (k = 0; k < cavp->lt[test]; ++k)
                if (buffer_t[k] != cavp->t[test][k])
                    correct = 0;
        }
        else if (!cavp->f[test])
        {
            for (k = 0; k < cavp->lp[test]; ++k)
                if (buffer[k] != cavp->p[test][k])
                    correct = 0;

            correct = (returnv == 0) ? 1 :
                (correct == 0) ? 1 : 0;
        }
        else // if (cavp->f[test])
        {
            correct = (returnv != 0) ? 1 : 0;
        }
    }

    if (verbose)
    {
        if (sel == CBC_OPERATION_MODE ||
            sel == GCM_OPERATION_MODE)
        {
            printf("i: ");
            for (k = 0; k < cavp->li[test]; ++k)
                printf("%02x ", cavp->i[test][k].to_uint());
            printf("\n");
        }

        if (sel == GCM_OPERATION_MODE)
        {
             printf("t: ");
             for (k = 0; k < cavp->lt[test]; ++k)
                 printf("%02x ", cavp->t[test][k].to_uint());
             printf("\n");

             printf("a: ");
             for (k = 0; k < cavp->la[test]; ++k)
                 printf("%02x ", cavp->a[test][k].to_uint());
             printf("\n");
        }

        printf("k: ");
        for (k = 0; k < cavp->lk[test]; ++k)
            printf("%02x ", cavp->k[test][k].to_uint());
        printf("\n");

        printf("p: ");
        for (k = 0; k < cavp->lp[test]; ++k)
            printf("%02x ", cavp->p[test][k].to_uint());
        printf("\n");

        printf("c: ");
        for (k = 0; k < cavp->lc[test]; ++k)
            printf("%02x ", cavp->c[test][k].to_uint());
        printf("\n");

        if (encryption)
        {
            printf("b: ");
            for (k = 0; k < cavp->lc[test]; ++k)
                printf("%02x ", buffer[k].to_uint());
            printf("\n");

            if (sel == GCM_OPERATION_MODE)
            {
                printf("t: ");
                for (k = 0; k < cavp->lt[test]; ++k)
                    printf("%02x ", buffer_t[k].to_uint());
                printf("\n");
            }
        }
        else
        {
            printf("b: ");
            for (k = 0; k < cavp->lp[test]; ++k)
                printf("%02x ", buffer[k].to_uint());
            printf("\n");
        }

        printf("%s: %s\n",
            (encryption)? "encryption" : "decryption",
            (correct == 1)? "succeeded" : "failed");
    }

    return correct;
}

void free_cavp(cavp_data *cavp, int sel)
{
    unsigned i = 0;

    if (sel == CBC_OPERATION_MODE ||
        sel == GCM_OPERATION_MODE)
    {
        free(cavp->li);
        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->i[i]);
        free(cavp->i);
    }

    if (sel == GCM_OPERATION_MODE)
    {
        free(cavp->f);

        free(cavp->lt);
        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->t[i]);
        free(cavp->t);

        free(cavp->la);
        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->a[i]);
        free(cavp->a);
    }

    free(cavp->lk);
    for (i = 0; i < cavp->tot_tests; ++i)
        free(cavp->k[i]);
    free(cavp->k);

    free(cavp->lp);
    for (i = 0; i < cavp->tot_tests; ++i)
        free(cavp->p[i]);
    free(cavp->p);

    free(cavp->lc);
    for (i = 0; i < cavp->tot_tests; ++i)
        free(cavp->c[i]);
    free(cavp->c);
}

#endif /* __UTILS_H__ */
