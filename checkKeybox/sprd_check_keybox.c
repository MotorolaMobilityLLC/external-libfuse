#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sprd_fts_type.h"
#include "sprd_fts_diag.h"
#include "sprd_fts_log.h"


char argv1[10];
#define CHECK_PRINT(fmt, ...)               \
  do {                                       \
    ALOGD("%s: " fmt, argv1, ##__VA_ARGS__); \
  } while (0)

extern uint32_t TEECex_SendMsg_To_TEE(uint8_t* msg,uint32_t msg_len,uint8_t* rsp, uint32_t* rsp_len);
#define TEE_TA_UUID_LENGTH             (16)
#define TEE_MSG_CHECK_LENGTH           (0x00000019)
#define TEE_MSG_CHECK_ID               (0x000F)
#define TEE_MSG_CHECK_WIDEVINE         (0x0010)
#define TEE_MSG_INIT_STORAGE           (0x0011)
#define TEE_MSG_CHECK_FLAG             (0x80)
#define TEE_MSG_CHECK_COM_ID           (0x1000000F)
#define TEE_MSG_CHECK_WIDEVINE_COM_ID  (0x10000010)
#define TEE_MSG_INIT_COM_ID            (0x10000011)
#define TEE_MSG_CHECK_ROTPK            (0x0104)
#define TEE_MSG_CHECK_ROTPK_FLAG       (0x81)
#define TEE_MSG_CHECK_ROTPK_COM_ID     (0x10000104)

#define TEE_MSG_CHECK_VERSION (0x0)

uint8_t ta_uuid[16] = {0xA0, 0x00, 0x00, 0x4e, 0x04, 0x01, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

#define TEE_RSP_CHECK_LENGTH          (0x0000000C)
#define TEE_RSP_CHECK_ID              (0x800F)
#define TEE_RSP_CHECK_WIDEVINE        (0x8010)
#define TEE_RSP_INIT_ID               (0x8011)
#define TEE_RSP_CHECK_ROTPK           (0x8104)
#define TEE_RSP_CHECK_FLAG            (0x00)

struct tee_msg_t {
    uint32_t length;
    uint16_t id;
    uint8_t  flag;
    uint8_t  ta_uuid[16];
    uint32_t com_id;
    uint8_t  version;
    uint8_t  xor;
};

struct tee_rsp_t {
    uint32_t length;
    uint16_t id;
    uint8_t  flag;
    uint32_t ret_code;
    uint8_t  xor;
};

static uint8_t *sec_memcpy_invert(uint8_t *dest, const uint8_t *src, unsigned int count)
{
    char *tmp = dest;
    const char *s = src+count-1;

    while (count--)
        *tmp++ = *s--;
    return dest;
}

int check_user_handle_common(uint16_t id, uint32_t com_id, uint8_t flag) {
    int i;
    struct tee_msg_t tee_msg;
    struct tee_rsp_t tee_rsp;
    uint8_t *msg_ptr;
    uint8_t tee_msg_buf[TEE_MSG_CHECK_LENGTH + 4];
    uint8_t tee_rsp_buf[TEE_RSP_CHECK_LENGTH + 4];
    uint32_t tee_rsp_len = 0;
    int ret = -1;
    uint8_t xor_data = 0;
    uint8_t *rsp_ptr = NULL;

    tee_msg.length  = TEE_MSG_CHECK_LENGTH;
    tee_msg.id      = id;
    tee_msg.flag    = flag;
    tee_msg.com_id  = com_id;
    tee_msg.version = TEE_MSG_CHECK_VERSION;
    tee_msg.xor     = 0;
    memcpy(tee_msg.ta_uuid, ta_uuid, TEE_TA_UUID_LENGTH);
    msg_ptr = (uint8_t *)&tee_msg;

    for (i = 0; i < tee_msg.length - 1; i++)
    {
        tee_msg.xor ^= msg_ptr[i];
    }

    sec_memcpy_invert(tee_msg_buf, (uint8_t *)&tee_msg.length, sizeof(uint32_t));
    sec_memcpy_invert(tee_msg_buf + 4,(uint8_t *)&tee_msg.id, sizeof(uint16_t));
    sec_memcpy_invert(tee_msg_buf + 6, (uint8_t *)&tee_msg.flag, sizeof(uint8_t));
    sec_memcpy_invert(tee_msg_buf + 7, (uint8_t *)tee_msg.ta_uuid, sizeof(uint8_t) * 16);
    sec_memcpy_invert(tee_msg_buf + 23, (uint8_t *)&tee_msg.com_id, sizeof(uint32_t));
    sec_memcpy_invert(tee_msg_buf + 27, (uint8_t *)&tee_msg.version, sizeof(uint8_t));
    sec_memcpy_invert(tee_msg_buf + 28, (uint8_t *)&tee_msg.xor, sizeof(uint8_t));

    CHECK_PRINT("%s: tee_msg_len=%d\n", __FUNCTION__, tee_msg.length);

    memset((uint8_t *)&tee_rsp, 0x0, sizeof(struct tee_rsp_t));
    memset((uint8_t *)&tee_rsp_buf, 0x0, (size_t)(TEE_RSP_CHECK_LENGTH + 4));
    ret =  TEECex_SendMsg_To_TEE((uint8_t *)tee_msg_buf, tee_msg.length,
                                    (uint8_t *)tee_rsp_buf, &tee_rsp_len);
    /*when calls production CA error, we will regard as secure disable*/
    if(0 != ret){
        CHECK_PRINT("%s: TEECex_SendMsg_To_TEE() error : %d \n", __FUNCTION__,ret);
        return 0;
    }

    memcpy((uint8_t *)&tee_rsp.length, tee_rsp_buf, sizeof(uint32_t));
    memcpy((uint8_t *)&tee_rsp.id, tee_rsp_buf + 4, sizeof(uint16_t));
    memcpy((uint8_t *)&tee_rsp.flag, tee_rsp_buf + 6, sizeof(uint8_t));
    memcpy((uint8_t *)&tee_rsp.ret_code, tee_rsp_buf + 7, sizeof(uint32_t));
    memcpy((uint8_t *)&tee_rsp.xor, tee_rsp_buf + 11, sizeof(uint8_t));

    CHECK_PRINT("%s: length: 0x%x, id: 0x%x, flag: 0x%x, ret_code: 0x%x, xor: 0x%x\n",
                __FUNCTION__, tee_rsp.length, tee_rsp.id, tee_rsp.flag, tee_rsp.ret_code, tee_rsp.xor);

    /*only production CA git rsp is 1, we regard as secure enabled, other is disabled*/
    if(1 == tee_rsp.ret_code) {
        CHECK_PRINT("%s: TEECex_SendMsg_To_TEE() success \n", __FUNCTION__);
        return 1;
    } else {
        CHECK_PRINT("%s: TEECex_SendMsg_To_TEE() error, tee_rsp.ret_code: %d\n", __FUNCTION__,tee_rsp.ret_code);
        return 0;
    }
}

int check_keybox_storage_init(void) {
    return check_user_handle_common(TEE_MSG_INIT_STORAGE, TEE_MSG_INIT_COM_ID, TEE_MSG_CHECK_FLAG);
}

int check_keybox_is_enabled(void) {
    return check_user_handle_common(TEE_MSG_CHECK_ID, TEE_MSG_CHECK_COM_ID, TEE_MSG_CHECK_FLAG);
}

int check_widevine_is_enabled(void) {
    return check_user_handle_common(TEE_MSG_CHECK_WIDEVINE, TEE_MSG_CHECK_WIDEVINE_COM_ID, TEE_MSG_CHECK_FLAG);
}

int check_Rotpk_is_enabled(void) {
    return check_user_handle_common(TEE_MSG_CHECK_ROTPK, TEE_MSG_CHECK_ROTPK_COM_ID, TEE_MSG_CHECK_ROTPK_FLAG);
}

int sprd_check_keybox(char *buf, int len, char *rsp, int rsplen)
{
    MSG_HEAD_T *msg_head_ptr;
    uint data = 0x0;
    if(1 == check_keybox_storage_init()){
        if(1 == check_keybox_is_enabled()){
            data = 0x1;
        }
    }

    CHECK_PRINT("sprd_check_keybox enter\n");
    memcpy(rsp, buf, 1 + sizeof(MSG_HEAD_T)+ sizeof(unsigned int));
    memcpy(rsp + 1 + sizeof(MSG_HEAD_T)+ sizeof(unsigned int), &data, sizeof(uint));
    msg_head_ptr = (MSG_HEAD_T *)(rsp + 1);
    msg_head_ptr->len+=4;
    rsp[msg_head_ptr->len + 2 - 1]=0x7E;
    CHECK_PRINT("check return len:%d\n",msg_head_ptr->len + 2);
    return msg_head_ptr->len + 2;
}

int sprd_check_widevine(char *buf, int len, char *rsp, int rsplen)
{
    MSG_HEAD_T *msg_head_ptr;
    uint data = 0x0;
    if(1 == check_keybox_storage_init()){
        if(1 == check_widevine_is_enabled()){
            data = 0x1;
        }
    }

    CHECK_PRINT("sprd_check_widevine enter\n");
    memcpy(rsp, buf, 1 + sizeof(MSG_HEAD_T)+ sizeof(unsigned int));
    memcpy(rsp + 1 + sizeof(MSG_HEAD_T)+ sizeof(unsigned int), &data, sizeof(uint));
    msg_head_ptr = (MSG_HEAD_T *)(rsp + 1);
    msg_head_ptr->len+=4;
    rsp[msg_head_ptr->len + 2 - 1]=0x7E;
    CHECK_PRINT("check return len:%d\n",msg_head_ptr->len + 2);
    return msg_head_ptr->len + 2;
}

int sprd_check_Rotpk(char *buf, int len, char *rsp, int rsplen)
{
    MSG_HEAD_T *msg_head_ptr;
    unsigned char data = 0x0;
    if(1 == check_Rotpk_is_enabled()){
            data = 0x1;
    }

    CHECK_PRINT("sprd_check_Rotpk enter\n");
    memcpy(rsp, buf, 1 + sizeof(MSG_HEAD_T));
    memcpy(rsp + 1 + sizeof(MSG_HEAD_T), &data, sizeof(unsigned char));
    msg_head_ptr = (MSG_HEAD_T *)(rsp + 1);
    msg_head_ptr->len+=1;
    rsp[msg_head_ptr->len + 2 - 1]=0x7E;
    CHECK_PRINT("check return len:%d\n",msg_head_ptr->len + 2);
    return msg_head_ptr->len + 2;
}

void register_this_module_ext(struct eng_callback *reg, int *num)
{
    CHECK_PRINT("register_this_module enter :libcheckkeybox\n");
    int modules_num = 0;

    reg->type = 0x5D; //main cmd
    reg->subtype = 0x2; //sub cmd
    reg->diag_ap_cmd = 0x3; // check keybox query
    reg->eng_diag_func = sprd_check_keybox; // rsp function ptr
    modules_num++;

    (reg+modules_num)->type = 0x5D; //main cmd
    (reg+modules_num)->subtype = 0x2; //sub cmd
    (reg+modules_num)->diag_ap_cmd = 0x4; // check widevine query
    (reg+modules_num)->eng_diag_func = sprd_check_widevine; // rsp function ptr
    modules_num++;

    (reg+modules_num)->type = 0x5; //main cmd
    (reg+modules_num)->subtype = 0x24; //sub cmd
    (reg+modules_num)->eng_diag_func = sprd_check_Rotpk; // rsp function ptr
    modules_num++;

    *num = modules_num;

    CHECK_PRINT("register_this_module_ext: %d : %d",*num, modules_num);
}
