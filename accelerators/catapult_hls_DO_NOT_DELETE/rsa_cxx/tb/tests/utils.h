#ifndef __UTILS_H__
#define __UTILS_H__

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

// These constants are used to distinguish the different types of
// tests from the NIST Cryptographic Algorithm Validation Program.

#define RSA_SASP    1
#define RSA_SIGGEN  2
#define RSA_SIGVER  3

// The following struct contains information about the test vectors.
// Not all the fields are used all the times. Check above to see the
// fields that are used depending on the specific test being run.

typedef struct {

    /* Total number of tests */
    unsigned tot_tests;

    /* Modulos */
    uint8_t **n;
    uint32_t *ln;

    /* Publ Exponent */
    uint8_t **e;
    uint32_t *le;

	/* Priv Exponent */
	uint8_t **d;
    uint32_t *ld;

    /* Plaintext */
    uint8_t **p;
    uint32_t *lp;

    /* Ciphertext */
    uint8_t **c;
    uint32_t *lc;

    /* Algorithm */
    char **a;

    /* Failure */
    bool *f;

} cavp_data;

void parse_cavp(cavp_data *cavp, const char *filename, uint8_t sel)
{
    char buf[3];
    char *token;
    size_t len = 0;
    unsigned i, j = 0;
    char *line = NULL;

    FILE *file = fopen(filename, "r");

    if (file == NULL)
    {
        fprintf(stderr, "Error: %s cannot be open\n", filename);
        exit(1);
    }

    cavp->n = NULL;
    cavp->e = NULL;
    cavp->d = NULL;
    cavp->p = NULL;
    cavp->c = NULL;
    cavp->ln = NULL;
    cavp->le = NULL;
    cavp->ld = NULL;
    cavp->lp = NULL;
    cavp->lc = NULL;
    cavp->a = NULL;
    cavp->f = NULL;
    cavp->tot_tests = 0;

    if (sel == RSA_SASP)
    {
        const int num_tests = 30; /* sasp */

        cavp->f = (bool*) malloc(num_tests * sizeof(bool));
        cavp->n = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->d = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->p = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->c = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->ln = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->ld = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->lp = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->lc = (uint32_t*) malloc(num_tests * sizeof(uint32_t));

        while (getline(&line, &len, file) != -1)
        {
            if (strstr(line, "n ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->tot_tests += 1;
                cavp->n[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->ln[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->n)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "d =") && (!strstr(line, "mod =")))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

 	            cavp->d[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->ld[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->d)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "EM ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

 	            cavp->p[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lp[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->p)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "S = FAIL"))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->f[cavp->tot_tests - 1] = true;
                cavp->c[cavp->tot_tests - 1] = NULL;
                cavp->lc[cavp->tot_tests - 1] = 0;
            }
            else if (strstr(line, "S ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->f[cavp->tot_tests - 1] = false;

 	            cavp->c[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lc[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->c)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }

            len = 0;
            free(line);
            line = NULL;
        }
    }
    else if (sel == RSA_SIGGEN)
    {
        /* const int num_tests = 80; */ /* siggen - rsa 3*/
        const int num_tests = 250;      /* siggen - rsa 2*/
        unsigned int current_n = 0;

        cavp->tot_tests += 1;
        cavp->a = (char**) malloc(num_tests * sizeof(char*));
        cavp->f = (bool*) malloc(num_tests * sizeof(bool));
        cavp->n = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->d = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->p = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->c = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->ln = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->ld = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->lp = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->lc = (uint32_t*) malloc(num_tests * sizeof(uint32_t));

        while (getline(&line, &len, file) != -1)
        {
            if (strstr(line, "n ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                current_n = cavp->tot_tests - 1;

                cavp->n[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->ln[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->n)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "SHAAlg ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if (current_n != cavp->tot_tests - 1)
                {
                    // This is required to use the old value of n
                    cavp->n[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * cavp->ln[current_n]);
                    cavp->ln[cavp->tot_tests - 1] = cavp->ln[current_n];

                    memcpy(cavp->n[cavp->tot_tests - 1],
                          cavp->n[current_n], cavp->ln[current_n]);

                    // This is required to use the old value of d
                    cavp->d[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * cavp->ld[current_n]);
                    cavp->ld[cavp->tot_tests - 1] = cavp->ld[current_n];

                    memcpy(cavp->d[cavp->tot_tests - 1],
                          cavp->d[current_n], cavp->ld[current_n]);
                }

 	            cavp->a[cavp->tot_tests - 1] = (char*) malloc(
                         sizeof(char) * strlen(token));
                strncpy(cavp->a[cavp->tot_tests - 1],
                        token, strlen(token));
            }
            else if (strstr(line, "d =") && (!strstr(line, "mod =")))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

 	            cavp->d[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->ld[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->d)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "Msg ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

 	            cavp->p[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lp[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->p)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "S ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                cavp->f[cavp->tot_tests - 1] = false;
 	            cavp->c[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lc[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->c)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }

                cavp->tot_tests += 1;
            }

            len = 0;
            free(line);
            line = NULL;
        }

		cavp->tot_tests -= 1;
    }
    else if (sel == RSA_SIGVER)
    {
        char *tmp;
        int allocated = 0;
        const int num_tests = 450;       /* sigver - rsa 2 */
        /* const int num_tests = 350; */ /* sigver - rsa 3*/
        unsigned int current_n = 0;

        cavp->tot_tests += 1;
        cavp->f = (bool*) malloc(num_tests * sizeof(bool));
        cavp->a = (char**) malloc(num_tests * sizeof(char*));
        cavp->n = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->e = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->p = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->c = (uint8_t**) malloc(num_tests * sizeof(uint8_t*));
        cavp->ln = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->le = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->lp = (uint32_t*) malloc(num_tests * sizeof(uint32_t));
        cavp->lc = (uint32_t*) malloc(num_tests * sizeof(uint32_t));

        while (getline(&line, &len, file) != -1)
        {
            if (strstr(line, "n ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                current_n = cavp->tot_tests - 1;

                cavp->n[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->ln[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->n)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }
            }
            else if (strstr(line, "SHAAlg ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

 	            cavp->a[cavp->tot_tests - 1] = (char*) malloc(
                         sizeof(char) * strlen(token));
                strncpy(cavp->a[cavp->tot_tests - 1],
                        token, strlen(token));

                if (current_n != cavp->tot_tests - 1)
                {
                    // This is required to use the old value of n
                    cavp->n[cavp->tot_tests - 1] = (uint8_t*) malloc(
                            sizeof(uint8_t) * cavp->ln[current_n]);
                    cavp->ln[cavp->tot_tests - 1] = cavp->ln[current_n];

                    memcpy(cavp->n[cavp->tot_tests - 1],
                          cavp->n[current_n], cavp->ln[current_n]);
                }
            }
            else if (strstr(line, "e ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if ((strlen(token) - 1) % 2)
                {
                    allocated = 1;
                    /* Prep a 0 so that the string has an even number of char*/
                    tmp = (char*) malloc(sizeof(char) * (strlen(token) + 2));
                    tmp[0] = '0'; strcpy(tmp + 1, token); token = tmp;
                }

 	            cavp->e[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->le[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->e)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }

                if (allocated)
                {
                    allocated = 0;
                    free(tmp);
                }
            }
            else if (strstr(line, "Msg ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if ((strlen(token) - 1) % 2)
                {
                    allocated = 1;
                    /* Prep a 0 so that the string has an even number of char*/
                    tmp = (char*) malloc(sizeof(char) * (strlen(token) + 2));
                    tmp[0] = '0'; strcpy(tmp + 1, token); token = tmp;
                }

 	            cavp->p[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lp[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->p)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }

				if (allocated)
                {
                    allocated = 0;
                    free(tmp);
				}
            }
            else if (strstr(line, "S ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if ((strlen(token) - 1) % 2)
                {
                    allocated = 1;
                    /* Prep a 0 so that the string has an even number of char*/
                    tmp = (char*) malloc(sizeof(char) * (strlen(token) + 2));
                    tmp[0] = '0'; strcpy(tmp + 1, token); token = tmp;
                }

	            cavp->c[cavp->tot_tests - 1] = (uint8_t*) malloc(
                        sizeof(uint8_t) * (strlen(token) - 1) / 2);
                cavp->lc[cavp->tot_tests - 1] = ((strlen(token) - 1) / 2);

                for (i = 0, j = 0; i < strlen(token) - 1; i += 2, j += 1)
                {
                    buf[0] = token[i + 0];
                    buf[1] = token[i + 1];
                    (cavp->c)[cavp->tot_tests - 1][j] = strtoul(buf, NULL, 16);
                }

                if (allocated)
                {
                    allocated = 0;
                    free(tmp);
                }
            }
            else if (strstr(line, "Result ="))
            {
                buf[2] = '\0';
                token = strtok(line, " =\n");
                token = strtok(NULL, " =\n");

                if (token[0] == 'F')
                     cavp->f[cavp->tot_tests - 1] = true;
                else // token[0] == "P"
                     cavp->f[cavp->tot_tests - 1] = false;

                cavp->tot_tests += 1;
            }

            len = 0;
            free(line);
            line = NULL;
        }

		cavp->tot_tests -= 1;
    }

    fclose(file);
    free(line);
}

int eval_cavp(cavp_data *cavp, uint8_t *buffer, uint32_t len, int test,
        bool fail, int sel, bool verbose)
{
    unsigned k = 0;
    int correct = 1;

    if (sel == RSA_SIGVER)
    {
        correct = (fail == cavp->f[test]);
    }
    else
    {
        if (fail != cavp->f[test])
            correct = 0;

        if (!cavp->f[test])
        {
            for (k = 0; k < len; ++k)
                if (buffer[k] != cavp->c[test][k])
                    correct = 0;
        }
    }

    if (verbose && cavp->f[test])
    {
        printf("-----------------------------------------------------------\n");

        printf("failt: %d\n", cavp->f[test]);
        printf("failb: %d\n", fail);

        printf("test: %s\n", (correct == 1)? "succeeded" : "failed");

        printf("-----------------------------------------------------------\n");
    }

    if (verbose && !cavp->f[test])
    {
        printf("-----------------------------------------------------------\n");

        printf("n: ");
        for (k = 0; k < cavp->ln[test]; ++k)
            printf("%02x ", cavp->n[test][k]);
        printf("\n");

        if (sel == RSA_SASP ||
            sel == RSA_SIGGEN)
        {
            printf("d: ");
            for (k = 0; k < cavp->ld[test]; ++k)
                printf("%02x ", cavp->d[test][k]);
            printf("\n");

            printf("c: ");
            for (k = 0; k < len; ++k)
                printf("%02x ", cavp->c[test][k]);
            printf("\n");
        }

        if (sel == RSA_SIGVER)
        {
            printf("e: ");
            for (k = 0; k < cavp->le[test]; ++k)
                printf("%02x ", cavp->e[test][k]);
            printf("\n");

            printf("p: ");
            for (k = 0; k < len; ++k)
                printf("%02x ", cavp->p[test][k]);
            printf("\n");
        }

        printf("b: ");
        for (k = 0; k < len; ++k)
            printf("%02x ", buffer[k]);
        printf("\n");

        printf("test: %s\n", (correct == 1)? "succeeded" : "failed");

        printf("-----------------------------------------------------------\n");
    }

    return correct;
}

void free_cavp(cavp_data *cavp, int sel)
{
    unsigned i = 0;

    if (sel == RSA_SASP ||
        sel == RSA_SIGGEN)
    {
        free(cavp->f);

        if (sel != RSA_SASP)
        {
            for (i = 0; i < cavp->tot_tests; ++i)
                free(cavp->a[i]);
            free(cavp->a);
        }

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->n[i]);
        free(cavp->n);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->d[i]);
        free(cavp->d);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->p[i]);
        free(cavp->p);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->c[i]);
        free(cavp->c);

        free(cavp->ln);
        free(cavp->ld);
        free(cavp->lp);
        free(cavp->lc);
    }
	else if (sel == RSA_SIGVER)
	{
        free(cavp->f);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->a[i]);
        free(cavp->a);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->n[i]);
        free(cavp->n);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->e[i]);
        free(cavp->e);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->p[i]);
        free(cavp->p);

        for (i = 0; i < cavp->tot_tests; ++i)
            free(cavp->c[i]);
        free(cavp->c);

        free(cavp->ln);
        free(cavp->le);
        free(cavp->lp);
        free(cavp->lc);
    }
}

#endif /* __UTILS_H__ */
