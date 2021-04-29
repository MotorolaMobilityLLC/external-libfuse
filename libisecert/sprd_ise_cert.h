#ifndef _SPRD_ISE_CERT_H
#define _SPRD_ISE_CERT_H


#define DIAG_CMD_TYPE                    0x62
#define DIAG_CMD_SUBTYPE                 0x00
#define DIAG_AP_CMD_ISE_CERTIFICATE      0x00AA

#define DIAG_CMD_7E_7E_LEN      2

#define DIAG_ISE_CMD_EXEC_SUCCESS       0
#define DIAG_AP_FIELD_WRONG_FORMAT      0xFF00

#define STANDARD_LC_LE_LEN      2
#define EXTEND_LC_LE_LEN        4
#define LC_LE_LEN               EXTEND_LC_LE_LEN
#define APDU_CLA_OFFSET         0x00
#define APDU_INS_OFFSET         0x01
#define APDU_P1_OFFSET          0x02
#define APDU_P2_OFFSET          0x03
#define APDU_LC_OFFSET          0x04
#define APDU_LE_OFFSET          0x04
#define APDU_STATUS_LEN         2

#define CLA_ISE_CERTIFICATE      0x80

#define INS_SYSTEM_INIT                           0xA0
#define INS_GET_RANDOM                            0xA1
#define INS_ALG_SELF_INSPECT                      0xA2
#define INS_QUERY_LIFECYCLE_FLAG                  0xA4
#define INS_SET_UID                               0xA5
#define INS_QUERY_UID                             0xA6
#define INS_QUERY_FIRMWARE_STATUS                 0xA7
#define INS_DESTROY_KEYS                          0xA8
#define INS_CONFIG_PARAMS                         0xA9

#define INS_SM2_SIGNATURE                         0xB0
#define INS_SM2_VERIFY                            0xB1
#define INS_SM2_ENCRYPTION                        0xB2
#define INS_SM2_DECRYPTION                        0xB3
#define INS_SM2_NEGOTIATION_PHASE1_RESPONDER      0xB4
#define INS_SM2_NEGOTIATION_PHASE2_RESPONDER      0xB5

#define INS_SM3_INIT                              0xC0
#define INS_SM3_UPDATE                            0xC1
#define INS_SM3_FINAL                             0xC2

#define INS_SM4_INIT                              0xD0
#define INS_SM4_UPDATE                            0xD1
#define INS_SM4_FINAL                             0xD2

#define INS_KEY_MANAGE_GENERATE_KEY               0xE0
#define INS_KEY_MANAGE_UPDATE_KEY                 0xE1
#define INS_KEY_MANAGE_IMPORT_KEY                 0xE2
#define INS_KEY_MANAGE_EXPORT_KEY                 0xE3

#define INS_SENSITIVE_INFO_WRITE                  0xF0
#define INS_SENSITIVE_INFO_CLEAR                  0xF1
#define INS_SENSITIVE_INFO_READ                   0xF2

#define SUCCESS                    0x9000
#define ERR_NOT_SUPPORTED_CLA      0x6E00
#define ERR_NOT_SUPPORTED_INS      0x6D00
#define ERR_APDU_DRIVER_FAULT      0x66FF

typedef enum _apdu_case_t {
	WITH_LC_NO_LE,
	WITH_LE_NO_LC,
	WITH_LC_AND_LE,
	WITH_LE_MAY_LC
}apdu_case_t;

typedef struct _ise_req_header_t {
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
}ise_req_header_t;

typedef struct _ise_req_t {
	uint8_t *data;
	uint32_t len;
}ise_req_t;

typedef struct _ise_resp_t {
	uint8_t *data;
	uint32_t len;
	uint16_t status;
}ise_resp_t;

#define FW_APDU_DATA_MAX_SIZE      4096

#define ISE_AP_PARAMS_OFFSET      (1 + sizeof(MSG_HEAD_T))
#define ISE_REQ_DATA_OFFSET       (ISE_AP_PARAMS_OFFSET + sizeof(TOOLS_DIAG_AP_CMD_T))
#define ISE_RESP_DATA_OFFSET      (ISE_AP_PARAMS_OFFSET + sizeof(TOOLS_DIAG_AP_CNF_T))
#define ISE_REQ_HEADER_LEN        (sizeof(ise_req_header_t) + LC_LE_LEN)

#define GET_RANDOM_DATA_LEN                8
#define GET_RANDOM_EXPECT_DATA_REGION      4
#define GET_RANDOM_CMD_LEN                 (ISE_REQ_HEADER_LEN + GET_RANDOM_DATA_LEN + LC_LE_LEN)

#define ISE_IOCTL_CMD_POWER_ON      12
#define ISE_POWER_ON                _IO('U', ISE_IOCTL_CMD_POWER_ON)

#endif

