package im.uwrkaxlmjj.ui.wallet.model;

import android.text.TextUtils;
import com.alibaba.fastjson.JSON;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BillRecordDetailBean {
    private String amount;
    private String balance;
    private String bankInfo;
    private String corderId;
    private String createTime;
    private String dp;
    private String effectUserId;
    private String effectUserName;
    private String groupsName;
    private String groupsNumber;
    private Map<String, Object> infoMap;
    private String institutionCode;
    private String institutionName;
    private String orderId;
    private int orderType;
    private String originalAmount;
    private String payBankCode;
    private String payBankName;
    private String payBankNumber;
    private int payMode;
    private String recipientBankCode;
    private String recipientBankName;
    private String recipientBankNumber;
    private String refundType;
    private String remarks;
    private String serviceCharge;
    private int status;
    private String subInstitutionCode;
    private String subInstitutionName;
    private String updateTime;

    public String getSubInstitutionName() {
        return this.subInstitutionName;
    }

    public void setSubInstitutionName(String subInstitutionName) {
        this.subInstitutionName = subInstitutionName;
    }

    public String getSubInstitutionCode() {
        return this.subInstitutionCode;
    }

    public void setSubInstitutionCode(String subInstitutionCode) {
        this.subInstitutionCode = subInstitutionCode;
    }

    public String getRefundType() {
        return this.refundType;
    }

    public void setRefundType(String refundType) {
        this.refundType = refundType;
    }

    public int getRefundTypeInt() {
        String str = this.refundType;
        if (str == null || TextUtils.isEmpty(str)) {
            return 1;
        }
        return Integer.parseInt(this.refundType);
    }

    public String getBankInfo() {
        return this.bankInfo;
    }

    public void setBankInfo(String bankInfo) {
        this.bankInfo = bankInfo;
    }

    public Map<String, Object> getInfoMap() {
        if (this.infoMap == null && !TextUtils.isEmpty(getBankInfo())) {
            try {
                this.infoMap = (Map) JSON.parseObject(getBankInfo(), LinkedHashMap.class);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        Map<String, Object> map = this.infoMap;
        return map == null ? new HashMap() : map;
    }

    public Object getCardNumber() {
        Map<String, Object> map = getInfoMap();
        Iterator<Map.Entry<String, Object>> it = map.entrySet().iterator();
        if (!it.hasNext()) {
            return "";
        }
        Map.Entry<String, Object> e = it.next();
        Object va = e.getValue();
        return va != null ? va : "";
    }

    public String getShortCardNumber() {
        String card = getCardNumber() + "";
        if (TextUtils.isEmpty(card)) {
            return "";
        }
        if (card.length() > 4) {
            return card.substring(card.length() - 4);
        }
        return card;
    }

    public String getAmount() {
        return this.amount;
    }

    public void setAmount(String amount) {
        this.amount = amount;
    }

    public String getServiceCharge() {
        return this.serviceCharge;
    }

    public void setServiceCharge(String serviceCharge) {
        this.serviceCharge = serviceCharge;
    }

    public String getOriginalAmount() {
        return this.originalAmount;
    }

    public void setOriginalAmount(String originalAmount) {
        this.originalAmount = originalAmount;
    }

    public String getBalance() {
        return this.balance;
    }

    public void setBalance(String balance) {
        this.balance = balance;
    }

    public String getDp() {
        return this.dp;
    }

    public void setDp(String dp) {
        this.dp = dp;
    }

    public int getOrderType() {
        return this.orderType;
    }

    public void setOrderType(int orderType) {
        this.orderType = orderType;
    }

    public String getOrderId() {
        return this.orderId;
    }

    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public int getPayMode() {
        return this.payMode;
    }

    public void setPayMode(int payMode) {
        this.payMode = payMode;
    }

    public String getEffectUserId() {
        return this.effectUserId;
    }

    public void setEffectUserId(String effectUserId) {
        this.effectUserId = effectUserId;
    }

    public String getEffectUserName() {
        return this.effectUserName;
    }

    public void setEffectUserName(String effectUserName) {
        this.effectUserName = effectUserName;
    }

    public String getGroupsNumber() {
        return this.groupsNumber;
    }

    public void setGroupsNumber(String groupsNumber) {
        this.groupsNumber = groupsNumber;
    }

    public String getGroupsName() {
        return this.groupsName;
    }

    public void setGroupsName(String groupsName) {
        this.groupsName = groupsName;
    }

    public String getPayBankNumber() {
        return this.payBankNumber;
    }

    public void setPayBankNumber(String payBankNumber) {
        this.payBankNumber = payBankNumber;
    }

    public String getPayBankCode() {
        return this.payBankCode;
    }

    public void setPayBankCode(String payBankCode) {
        this.payBankCode = payBankCode;
    }

    public String getPayBankName() {
        return this.payBankName;
    }

    public void setPayBankName(String payBankName) {
        this.payBankName = payBankName;
    }

    public String getRecipientBankNumber() {
        return this.recipientBankNumber;
    }

    public String getSortBankNumber() {
        String str = this.recipientBankNumber;
        if (str == null) {
            return "";
        }
        if (str.length() <= 4) {
            return this.recipientBankNumber;
        }
        String str2 = this.recipientBankNumber;
        return str2.substring(str2.length() - 4);
    }

    public void setRecipientBankNumber(String recipientBankNumber) {
        this.recipientBankNumber = recipientBankNumber;
    }

    public String getRecipientBankCode() {
        return this.recipientBankCode;
    }

    public void setRecipientBankCode(String recipientBankCode) {
        this.recipientBankCode = recipientBankCode;
    }

    public String getRecipientBankName() {
        return this.recipientBankName;
    }

    public void setRecipientBankName(String recipientBankName) {
        this.recipientBankName = recipientBankName;
    }

    public String getInstitutionCode() {
        return this.institutionCode;
    }

    public void setInstitutionCode(String institutionCode) {
        this.institutionCode = institutionCode;
    }

    public String getInstitutionName() {
        return this.institutionName;
    }

    public void setInstitutionName(String institutionName) {
        this.institutionName = institutionName;
    }

    public String getRemarks() {
        return this.remarks;
    }

    public void setRemarks(String remarks) {
        this.remarks = remarks;
    }

    public String getCreateTime() {
        return this.createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public String getUpdateTime() {
        return this.updateTime;
    }

    public void setUpdateTime(String updateTime) {
        this.updateTime = updateTime;
    }

    public String getCorderId() {
        return this.corderId;
    }

    public void setCorderId(String corderId) {
        this.corderId = corderId;
    }

    public boolean isGroupRedPacketRefund() {
        if (this.orderType == 12) {
            return !TextUtils.isEmpty(this.groupsNumber);
        }
        return false;
    }

    public boolean isRedPacketRefund() {
        return this.orderType == 12;
    }

    public boolean isPersonalRedPacketRefund() {
        if (this.orderType != 12) {
            return false;
        }
        return TextUtils.isEmpty(this.groupsNumber);
    }

    public boolean isPartialRefund() {
        if (TextUtils.isEmpty(this.amount) || TextUtils.isEmpty(this.originalAmount)) {
            return false;
        }
        return !this.amount.equals(this.originalAmount);
    }

    public String getTypeStr() {
        int i = this.orderType;
        if (i == 0) {
            return LocaleController.getString(R.string.redpacket_go_recharge);
        }
        if (i == 1) {
            return LocaleController.getString(R.string.Withdrawal);
        }
        if (i == 3) {
            return LocaleController.getString(R.string.WithdrawalFailureRefund);
        }
        switch (i) {
            case 5:
                return "转账-进账";
            case 6:
                return "转账-支付";
            case 7:
                return "转账-退款";
            case 8:
                return "红包-领取";
            case 9:
                return "个人-红包支付";
            case 10:
                return "群-红包支付";
            case 11:
                return "群个人-红包支付";
            case 12:
                return "红包过期退款";
            case 13:
                return "平台上账";
            default:
                switch (i) {
                    case 19:
                        return "扫码转账->进账";
                    case 20:
                        return "扫码转账->支付";
                    case 21:
                        return "UChat团队";
                    case 22:
                        return "商户交易-收款";
                    case 23:
                        return "商户交易-付款";
                    case 24:
                        return "商户交易-退款";
                    default:
                        return LocaleController.getString(R.string.UnKnown);
                }
        }
    }

    public String getTypePrefix() {
        int i = this.orderType;
        if (i == 0) {
            return LocaleController.getString(R.string.redpacket_go_recharge);
        }
        if (i == 1 || i == 3) {
            return LocaleController.getString(R.string.Withdrawal);
        }
        switch (i) {
            case 5:
            case 6:
            case 7:
                return LocaleController.getString(R.string.Transfer);
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
                return LocaleController.getString(R.string.RedPacket);
            case 13:
                return "平台上账";
            default:
                switch (i) {
                    case 19:
                        return "扫码转账->进账";
                    case 20:
                        return "扫码转账->支付";
                    case 21:
                        return "UChat团队";
                    case 22:
                        return "商户交易-收款";
                    case 23:
                        return "商户交易-付款";
                    case 24:
                        return "商户交易-退款";
                    default:
                        return LocaleController.getString(R.string.UnKnown);
                }
        }
    }

    public int getTypeIcon() {
        int i = this.orderType;
        if (i == 1 || i == 20 || i == 23) {
            return R.id.ic_wallet_withdraw;
        }
        switch (i) {
        }
        return R.id.ic_wallet_withdraw;
    }
}
