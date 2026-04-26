#include <pbc/pbc.h>
#include <stdlib.h>

static const char TYPE_A_PARAM[] =
    "type a\n"
    "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
    "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
    "r 730750818665451621361119245571504901405976559617\n"
    "exp2 159\n"
    "exp1 107\n"
    "sign1 1\n"
    "sign0 1\n";

static pairing_t GLOBAL_PAIRING;
static element_t GLOBAL_G1;
static element_t GLOBAL_G2;
static int GLOBAL_INITIALIZED = 0;

static int ensure_initialized(void) {
    if (GLOBAL_INITIALIZED) {
        return 1;
    }
    if (pairing_init_set_str(GLOBAL_PAIRING, TYPE_A_PARAM)) {
        return 0;
    }
    element_init_G1(GLOBAL_G1, GLOBAL_PAIRING);
    element_init_G2(GLOBAL_G2, GLOBAL_PAIRING);
    element_from_hash(GLOBAL_G1, "dup_mix_g1", 10);
    element_from_hash(GLOBAL_G2, "dup_mix_g2", 10);
    GLOBAL_INITIALIZED = 1;
    return 1;
}

static int set_zr_from_decimal(element_t out, const char *decimal) {
    mpz_t value;
    mpz_init(value);
    if (mpz_set_str(value, decimal, 10) != 0) {
        mpz_clear(value);
        return 0;
    }
    element_set_mpz(out, value);
    mpz_clear(value);
    return 1;
}

int pbc_pairing_check_equal(
    const char *left_a,
    const char *left_b,
    const char *right_a,
    const char *right_b
) {
    // 实现论文中的基础配对等式验证：
    // e(g^left_a, h^left_b) == e(g^right_a, h^right_b)。
    // 用于用户身份验证和单块上传认证器验证。
    element_t left_g1, left_g2, right_g1, right_g2, zr_a, zr_b, zr_c, zr_d, lhs, rhs;
    int ok = 0;

    if (!ensure_initialized()) {
        return 0;
    }

    element_init_G1(left_g1, GLOBAL_PAIRING);
    element_init_G2(left_g2, GLOBAL_PAIRING);
    element_init_G1(right_g1, GLOBAL_PAIRING);
    element_init_G2(right_g2, GLOBAL_PAIRING);
    element_init_Zr(zr_a, GLOBAL_PAIRING);
    element_init_Zr(zr_b, GLOBAL_PAIRING);
    element_init_Zr(zr_c, GLOBAL_PAIRING);
    element_init_Zr(zr_d, GLOBAL_PAIRING);
    element_init_GT(lhs, GLOBAL_PAIRING);
    element_init_GT(rhs, GLOBAL_PAIRING);

    if (
        set_zr_from_decimal(zr_a, left_a) &&
        set_zr_from_decimal(zr_b, left_b) &&
        set_zr_from_decimal(zr_c, right_a) &&
        set_zr_from_decimal(zr_d, right_b)
    ) {
        element_pow_zn(left_g1, GLOBAL_G1, zr_a);
        element_pow_zn(left_g2, GLOBAL_G2, zr_b);
        element_pow_zn(right_g1, GLOBAL_G1, zr_c);
        element_pow_zn(right_g2, GLOBAL_G2, zr_d);
        pairing_apply(lhs, left_g1, left_g2, GLOBAL_PAIRING);
        pairing_apply(rhs, right_g1, right_g2, GLOBAL_PAIRING);
        ok = !element_cmp(lhs, rhs);
    }

    element_clear(left_g1);
    element_clear(left_g2);
    element_clear(right_g1);
    element_clear(right_g2);
    element_clear(zr_a);
    element_clear(zr_b);
    element_clear(zr_c);
    element_clear(zr_d);
    element_clear(lhs);
    element_clear(rhs);
    return ok;
}

int pbc_pairing_check_product(
    const char *left_exp,
    const char **bases,
    const char **ys,
    const char **coeffs,
    int count
) {
    // 实现论文审计 VerifyProof 公式：
    // e(g^left_exp, h) == prod_i e(g^base_i, h^Y_i)^{v_i}。
    // left_exp 对应 sigma_c，base_i 对应 H2(s||tg_i)*prod_j r_j^{c_i,j}。
    element_t left_g1, left_gt, rhs_gt, base_g1, y_g2, tmp_gt, pow_gt, zr_left, zr_base, zr_y, zr_coeff;
    int ok = 0;

    if (count < 0 || !ensure_initialized()) {
        return 0;
    }

    element_init_G1(left_g1, GLOBAL_PAIRING);
    element_init_G1(base_g1, GLOBAL_PAIRING);
    element_init_G2(y_g2, GLOBAL_PAIRING);
    element_init_GT(left_gt, GLOBAL_PAIRING);
    element_init_GT(rhs_gt, GLOBAL_PAIRING);
    element_init_GT(tmp_gt, GLOBAL_PAIRING);
    element_init_GT(pow_gt, GLOBAL_PAIRING);
    element_init_Zr(zr_left, GLOBAL_PAIRING);
    element_init_Zr(zr_base, GLOBAL_PAIRING);
    element_init_Zr(zr_y, GLOBAL_PAIRING);
    element_init_Zr(zr_coeff, GLOBAL_PAIRING);

    if (set_zr_from_decimal(zr_left, left_exp)) {
        element_pow_zn(left_g1, GLOBAL_G1, zr_left);
        pairing_apply(left_gt, left_g1, GLOBAL_G2, GLOBAL_PAIRING);
        element_set1(rhs_gt);
        ok = 1;
        for (int i = 0; i < count; i++) {
            if (
                !set_zr_from_decimal(zr_base, bases[i]) ||
                !set_zr_from_decimal(zr_y, ys[i]) ||
                !set_zr_from_decimal(zr_coeff, coeffs[i])
            ) {
                ok = 0;
                break;
            }
            element_pow_zn(base_g1, GLOBAL_G1, zr_base);
            element_pow_zn(y_g2, GLOBAL_G2, zr_y);
            pairing_apply(tmp_gt, base_g1, y_g2, GLOBAL_PAIRING);
            element_pow_zn(pow_gt, tmp_gt, zr_coeff);
            element_mul(rhs_gt, rhs_gt, pow_gt);
        }
        ok = ok && !element_cmp(left_gt, rhs_gt);
    }

    element_clear(left_g1);
    element_clear(base_g1);
    element_clear(y_g2);
    element_clear(left_gt);
    element_clear(rhs_gt);
    element_clear(tmp_gt);
    element_clear(pow_gt);
    element_clear(zr_left);
    element_clear(zr_base);
    element_clear(zr_y);
    element_clear(zr_coeff);
    return ok;
}
