#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm-generic/ioctl.h>
#include "sprd_fts_type.h"
#include "sprd_fts_log.h"
#include "sprd_ise_cert.h"


bool first_bootup = true;

static int check_diag_package_format(MSG_HEAD_T *req_msg_head, TOOLS_DIAG_AP_CMD_T *ap_cmd, short len)
{
	if (req_msg_head->type != DIAG_CMD_TYPE ||
		req_msg_head->subtype != DIAG_CMD_SUBTYPE ||
		req_msg_head->len != (len - DIAG_CMD_7E_7E_LEN) ||
		ap_cmd->cmd != DIAG_AP_CMD_ISE_CERTIFICATE ||
		ap_cmd->length != (len - sizeof(MSG_HEAD_T) - sizeof(TOOLS_DIAG_AP_CMD_T) - DIAG_CMD_7E_7E_LEN))
	    return -1;

	return 0;
}

static uint32_t organize_diag_package(MSG_HEAD_T *req_msg_head, uint16_t status, uint16_t resplen, char *resp)
{
	MSG_HEAD_T *resp_msg_head = (MSG_HEAD_T *)(resp + 1);
	TOOLS_DIAG_AP_CNF_T *ap_cnf = (TOOLS_DIAG_AP_CNF_T *)(resp + ISE_AP_PARAMS_OFFSET);

	resp[0] = 0x7E;
	memcpy((uint8_t *)resp_msg_head, (uint8_t *)req_msg_head, sizeof(MSG_HEAD_T));
	resp_msg_head->len = sizeof(MSG_HEAD_T) + sizeof(TOOLS_DIAG_AP_CNF_T) + resplen;
	ap_cnf->status = status;
	ap_cnf->length = resplen;
	resp[1 + resp_msg_head->len] = 0x7E;

	return resp_msg_head->len + DIAG_CMD_7E_7E_LEN;
}

static void set_resp_len(ise_req_t *req, ise_resp_t *resp, apdu_case_t apdu_case)
{
	uint32_t lc;

	switch (apdu_case) {
		case WITH_LC_NO_LE:
			resp->len = APDU_STATUS_LEN;
			break;

		case WITH_LE_NO_LC:
			resp->len = *((uint32_t *)(req->data + APDU_LE_OFFSET)) + APDU_STATUS_LEN;
			break;

		case WITH_LC_AND_LE:
			lc = *((uint32_t *)(req->data + APDU_LC_OFFSET));
			resp->len = *((uint32_t *)(req->data + ISE_REQ_HEADER_LEN + lc)) + APDU_STATUS_LEN;
			break;

		case WITH_LE_MAY_LC:
			lc = *((uint32_t *)(req->data + APDU_LC_OFFSET));
			if (lc > (req->len - 8)) //with le, no lc
				resp->len = *((uint32_t *)(req->data + APDU_LE_OFFSET)) + APDU_STATUS_LEN;
			else //with lc and le
				resp->len = *((uint32_t *)(req->data + ISE_REQ_HEADER_LEN + lc)) + APDU_STATUS_LEN;
			break;
	}
}

static uint32_t apdu_process(ise_req_t *req, ise_resp_t *resp)
{
	int fd;
	int len;
	uint32_t value;

	fd = open("/dev/apdu", O_RDWR);
	if (fd < 0) {
		ENG_LOG("open %s failed!\n", "dev/apdu");
		goto OPEN_FAIL;
	}

	if (first_bootup == true) {
		if (ioctl(fd, ISE_POWER_ON, &value) < 0) {
			ENG_LOG("%s process ioctl failed!\n", "dev/apdu");
			goto PROCESS_FAIL;
		}

		first_bootup = false;
	}

	//send apdu command to ise
	len = write(fd, req->data, req->len);
	if (len != req->len) {
		ENG_LOG("send %s failed, actual_len: 0x%x, expected_len: 0x%x!\n", "dev/apdu", len, req->len);
		goto PROCESS_FAIL;
	}

	//receive apdu response from ise
	len = read(fd, resp->data, resp->len);
	if (len < 0) {
		ENG_LOG("read %s failed!\n", "dev/apdu");
		goto PROCESS_FAIL;
	}
	resp->len = len;
	resp->status = *((uint16_t *)(resp->data + resp->len - APDU_STATUS_LEN));

	close(fd);

	return resp->len;

PROCESS_FAIL:
	close(fd);
OPEN_FAIL:
	*((uint32_t *)resp->data) = ERR_APDU_DRIVER_FAULT;
	resp->status = ERR_APDU_DRIVER_FAULT;
	resp->len = APDU_STATUS_LEN;

	return resp->len;
}

static uint32_t get_random(ise_req_t *req, ise_resp_t *resp)
{
	uint16_t need_len = *((uint16_t *)(req->data + ISE_REQ_HEADER_LEN + GET_RANDOM_DATA_LEN));
	uint32_t count = need_len / FW_APDU_DATA_MAX_SIZE;
	uint32_t res = need_len  % FW_APDU_DATA_MAX_SIZE;
	ise_req_t transfer_req;
	uint32_t resp_len = 0;
	uint32_t i;

	transfer_req.data = (uint8_t *)malloc(sizeof(uint8_t) * GET_RANDOM_CMD_LEN);
	memcpy(transfer_req.data, req->data, ISE_REQ_HEADER_LEN); //cla|ins|p1|p2
	*((uint32_t *)(transfer_req.data + ISE_REQ_HEADER_LEN)) = GET_RANDOM_DATA_LEN; //lc
	memcpy(transfer_req.data + ISE_REQ_HEADER_LEN, req->data + ISE_REQ_HEADER_LEN, GET_RANDOM_DATA_LEN); //data
	transfer_req.len = GET_RANDOM_CMD_LEN;

	//get random
	if (count != 0) {
		*((uint32_t *)(transfer_req.data + ISE_REQ_HEADER_LEN + GET_RANDOM_EXPECT_DATA_REGION)) = FW_APDU_DATA_MAX_SIZE; //re-assign data, should be equal to le
		*((uint32_t *)(transfer_req.data + ISE_REQ_HEADER_LEN + GET_RANDOM_DATA_LEN)) = FW_APDU_DATA_MAX_SIZE; //le
		resp->len = FW_APDU_DATA_MAX_SIZE + APDU_STATUS_LEN;
	}
	for (i = 0; i < count; i++) {
		resp_len += apdu_process(&transfer_req, resp);
		if (resp->status != SUCCESS) {
			ENG_LOG("random process fail, count=0x%x!\n", i);
			resp_len = APDU_STATUS_LEN;
			goto PROCESS_ERR;
		}

		resp->data += FW_APDU_DATA_MAX_SIZE;

		if (res != 0) {
			resp_len -= APDU_STATUS_LEN; //reduce 2 bytes for "9000"
		} else {
			if (i != (count -1))
				resp_len -= APDU_STATUS_LEN; //reduce 2 bytes for "9000"
		}
	}

	//get random
	if (res != 0) {
		*((uint32_t *)(transfer_req.data + ISE_REQ_HEADER_LEN + GET_RANDOM_EXPECT_DATA_REGION)) = res; //re-assign data, should be equal to le
		*((uint32_t *)(transfer_req.data + ISE_REQ_HEADER_LEN + GET_RANDOM_DATA_LEN)) = res; //le
		resp->len = res + APDU_STATUS_LEN;

		resp_len += apdu_process(&transfer_req, resp);
		if (resp->status != SUCCESS) {
			ENG_LOG("random process fail, res=0x%x!\n", res);
			resp_len = APDU_STATUS_LEN;
			goto PROCESS_ERR;
		}
	}

PROCESS_ERR:
	free(transfer_req.data);
	return resp_len;
}

static int sprd_ise_certificate_handler(char *buf, int len, char *rsp, int rsplen)
{
	ise_req_t ise_req;
	ise_resp_t ise_resp;
	uint32_t resp_len;
	int ret;

	if (buf == NULL || rsp == NULL) {
		ENG_LOG("%s: null pointer", __FUNCTION__);
		return 0;
	}

	//check diag package format
	MSG_HEAD_T *req_msg_head = (MSG_HEAD_T *)(buf + 1);
	TOOLS_DIAG_AP_CMD_T *ap_cmd= (TOOLS_DIAG_AP_CMD_T *)(buf + ISE_AP_PARAMS_OFFSET);
	ret = check_diag_package_format(req_msg_head, ap_cmd, len);
	if (ret != 0)
		return organize_diag_package(req_msg_head, DIAG_AP_FIELD_WRONG_FORMAT, 0, rsp);

	//initialize apdu struct
	ise_req_header_t *req_header = (ise_req_header_t *)(buf + ISE_REQ_DATA_OFFSET);
	ise_req.data = (uint8_t *)(buf + ISE_REQ_DATA_OFFSET);
	ise_req.len = ap_cmd->length;
	ise_resp.data = (uint8_t *)(rsp + ISE_RESP_DATA_OFFSET);

	//check apdu format
	if (req_header->cla != CLA_ISE_CERTIFICATE) {
		*((uint32_t *)ise_resp.data) = ERR_NOT_SUPPORTED_CLA;
		return organize_diag_package(req_msg_head, DIAG_ISE_CMD_EXEC_SUCCESS, APDU_STATUS_LEN, rsp);
	}

	//distribute apdu command
	switch (req_header->ins) {
		/* only have lc, no le */
		case INS_ALG_SELF_INSPECT:
		case INS_SET_UID:
		case INS_DESTROY_KEYS:
		case INS_CONFIG_PARAMS:
		case INS_SM3_INIT:
		case INS_SM3_UPDATE:
		case INS_SM4_INIT:
		case INS_KEY_MANAGE_UPDATE_KEY:
		case INS_KEY_MANAGE_IMPORT_KEY:
		case INS_SENSITIVE_INFO_WRITE:
		case INS_SENSITIVE_INFO_CLEAR:
			set_resp_len(&ise_req, &ise_resp, WITH_LC_NO_LE);
			resp_len = apdu_process(&ise_req, &ise_resp);
			break;

		/* only have le, no lc */
		case INS_QUERY_LIFECYCLE_FLAG:
		case INS_QUERY_UID:
		case INS_QUERY_FIRMWARE_STATUS:
		case INS_SM3_FINAL:
		case INS_SENSITIVE_INFO_READ:
			set_resp_len(&ise_req, &ise_resp, WITH_LE_NO_LC);
			resp_len = apdu_process(&ise_req, &ise_resp);
			break;

		/* have lc and le */
		case INS_SYSTEM_INIT:
		case INS_SM2_SIGNATURE:
		case INS_SM2_VERIFY:
		case INS_SM2_ENCRYPTION:
		case INS_SM2_DECRYPTION:
		case INS_SM2_NEGOTIATION_PHASE1_RESPONDER:
		case INS_SM2_NEGOTIATION_PHASE2_RESPONDER:
		case INS_SM4_UPDATE:
		case INS_KEY_MANAGE_GENERATE_KEY:
		case INS_KEY_MANAGE_EXPORT_KEY:
			set_resp_len(&ise_req, &ise_resp, WITH_LC_AND_LE);
			resp_len = apdu_process(&ise_req, &ise_resp);
			break;

		/* have le, may have lc */
		case INS_SM4_FINAL:
			set_resp_len(&ise_req, &ise_resp, WITH_LE_MAY_LC);
			resp_len = apdu_process(&ise_req, &ise_resp);
			break;

		case INS_GET_RANDOM:
			resp_len = get_random(&ise_req, &ise_resp);
			break;

		default:
			*((uint32_t *)ise_resp.data) = ERR_NOT_SUPPORTED_INS;
			return organize_diag_package(req_msg_head, DIAG_ISE_CMD_EXEC_SUCCESS, APDU_STATUS_LEN, rsp);
	}

	return organize_diag_package(req_msg_head, DIAG_ISE_CMD_EXEC_SUCCESS, resp_len, rsp);
}

void register_this_module(struct eng_callback *reg)
{
    ENG_LOG("register_this_module :libisecert\n");

    reg->type = DIAG_CMD_TYPE;
    reg->subtype = DIAG_CMD_SUBTYPE;
    reg->diag_ap_cmd = DIAG_AP_CMD_ISE_CERTIFICATE;
    reg->eng_diag_func = sprd_ise_certificate_handler;
}

