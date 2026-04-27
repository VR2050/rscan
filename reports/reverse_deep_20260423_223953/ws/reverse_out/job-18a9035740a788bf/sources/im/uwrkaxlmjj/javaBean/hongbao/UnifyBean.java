package im.uwrkaxlmjj.javaBean.hongbao;

/* JADX INFO: loaded from: classes2.dex */
public class UnifyBean {
    public static final String API_VERSION = "0.0.1";
    public static final String BUSINESS_KEY_REDPACKET = "unified_order_red";
    public static final String BUSINESS_KEY_REDPACKET_CHECK = "check_red";
    public static final String BUSINESS_KEY_REDPACKET_DETAIL = "red_details";
    public static final String BUSINESS_KEY_REDPACKET_RECEIVE = "receive_red_v2";
    public static final String BUSINESS_KEY_REDPACKET_RECORDS = "red_records";
    public static final String BUSINESS_KEY_TRANSFER = "unified_order_carry_over";
    public static final String BUSINESS_KEY_TRANSFER_CHECK = "carry_over_details";
    public static final String BUSINESS_KEY_TRANSFER_RECEIVE = "rob_carry_over";
    public static final String BUSINESS_KEY_TRANSFER_REFUSE = "cancel_carry_over";
    public static final String REDPACKET_TRANSFER_API_VERSION = "1";
    public static final String REDPACKET_TRANSFER_API_VERSION_TEMP = "2.0.1";
    public static final String REDPKG_GROUP_PERSON_TYPE = "2";
    public static final String REDPKG_GROUP_TYPE = "1";
    public static final String REDPKG_PERSON_TYPE = "0";
    public static final String REDPKG_SEND_FIXAMOUNT_TYPE = "0";
    public static final String REDPKG_SEND_RANDOM_TYPE = "1";
    public static final String TRADE_REDPKG_TYPE = "1";
    public static final String TRADE_TRANSF_TYPE = "0";
    private String attach;
    private String body;
    private String businessKey;
    private String detail;
    private String initiator;
    private String nonceStr;
    private String outTradeNo;
    private String payPassWord;
    private String recipient;
    private String remarks;
    private String totalFee;
    private String tradeType;
    private String version;

    public String getRecipient() {
        return this.recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public String getDetail() {
        return this.detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public String getAttach() {
        return this.attach;
    }

    public void setAttach(String attach) {
        this.attach = attach;
    }

    public String getRemarks() {
        return this.remarks;
    }

    public void setRemarks(String remarks) {
        this.remarks = remarks;
    }

    public String getOutTradeNo() {
        return this.outTradeNo;
    }

    public void setOutTradeNo(String outTradeNo) {
        this.outTradeNo = outTradeNo;
    }

    public String getNonceStr() {
        return this.nonceStr;
    }

    public void setNonceStr(String nonceStr) {
        this.nonceStr = nonceStr;
    }

    public String getBody() {
        return this.body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getTotalFee() {
        return this.totalFee;
    }

    public void setTotalFee(String totalFee) {
        this.totalFee = totalFee;
    }

    public String getTradeType() {
        return this.tradeType;
    }

    public void setTradeType(String tradeType) {
        this.tradeType = tradeType;
    }

    public String getInitiator() {
        return this.initiator;
    }

    public void setInitiator(String initiator) {
        this.initiator = initiator;
    }

    public String getPayPassWord() {
        return this.payPassWord;
    }

    public void setPayPassWord(String payPassWord) {
        this.payPassWord = payPassWord;
    }

    public String getBusinessKey() {
        return this.businessKey;
    }

    public void setBusinessKey(String businessKey) {
        this.businessKey = businessKey;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version) {
        this.version = version;
    }
}
