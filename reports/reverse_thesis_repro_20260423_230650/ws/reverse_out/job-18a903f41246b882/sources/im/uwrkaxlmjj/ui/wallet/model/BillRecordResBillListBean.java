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
public class BillRecordResBillListBean {
    private int amount;
    private int balance;
    private String bankInfo;
    private String createTime;
    private String dp;
    private String effectUserId;
    private String effectUserName;
    private String groupsName;
    private String groupsNumber;
    private int id;
    private Map<String, Object> infoMap;
    private String institutionCode;
    private String institutionName;
    private String orderId;
    private int orderType;
    private int payMode;
    private String recipientBankNumber;
    private String refundAmount;
    private String refundType;
    private int serviceCharge;
    private int status;
    private String subInstitutionCode;
    private String subInstitutionName;
    private String updateTime;

    public String getBankInfo() {
        return this.bankInfo;
    }

    public void setBankInfo(String bankInfo) {
        this.bankInfo = bankInfo;
    }

    public String getRefundType() {
        return this.refundType;
    }

    public void setRefundType(String refundType) {
        this.refundType = refundType;
    }

    public String getRefundAmount() {
        return this.refundAmount;
    }

    public void setRefundAmount(String refundAmount) {
        this.refundAmount = refundAmount;
    }

    public String getGroupsNumber() {
        return this.groupsNumber;
    }

    public void setGroupsNumber(String groupsNumber) {
        this.groupsNumber = groupsNumber;
    }

    public int getOrderType() {
        return this.orderType;
    }

    public void setOrderType(int orderType) {
        this.orderType = orderType;
    }

    public int getAmount() {
        return this.amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public String getOrderId() {
        return this.orderId;
    }

    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    public int getPayMode() {
        return this.payMode;
    }

    public void setPayMode(int payMode) {
        this.payMode = payMode;
    }

    public String getGroupsName() {
        return this.groupsName;
    }

    public void setGroupsName(String groupsName) {
        this.groupsName = groupsName;
    }

    public String getUpdateTime() {
        return this.updateTime;
    }

    public void setUpdateTime(String updateTime) {
        this.updateTime = updateTime;
    }

    public String getDp() {
        return this.dp;
    }

    public void setDp(String dp) {
        this.dp = dp;
    }

    public int getServiceCharge() {
        return this.serviceCharge;
    }

    public void setServiceCharge(int serviceCharge) {
        this.serviceCharge = serviceCharge;
    }

    public String getEffectUserName() {
        return this.effectUserName;
    }

    public void setEffectUserName(String effectUserName) {
        this.effectUserName = effectUserName;
    }

    public int getBalance() {
        return this.balance;
    }

    public void setBalance(int balance) {
        this.balance = balance;
    }

    public String getInstitutionCode() {
        return this.institutionCode;
    }

    public void setInstitutionCode(String institutionCode) {
        this.institutionCode = institutionCode;
    }

    public String getCreateTime() {
        return this.createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public String getInstitutionName() {
        return this.institutionName;
    }

    public void setInstitutionName(String institutionName) {
        this.institutionName = institutionName;
    }

    public String getEffectUserId() {
        return this.effectUserId;
    }

    public void setEffectUserId(String effectUserId) {
        this.effectUserId = effectUserId;
    }

    public String getRecipientBankNumber() {
        return this.recipientBankNumber;
    }

    public void setRecipientBankNumber(String recipientBankNumber) {
        this.recipientBankNumber = recipientBankNumber;
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status) {
        this.status = status;
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
                return LocaleController.getString(R.string.TransferIncoming);
            case 6:
                return LocaleController.getString(R.string.TransferPay);
            case 7:
                return LocaleController.getString(R.string.TransferRefund2);
            case 8:
                return LocaleController.getString(R.string.RedPacketReceive);
            case 9:
                return LocaleController.getString(R.string.PersonalRedPacketPayment);
            case 10:
                return LocaleController.getString(R.string.GrouplRedPacketPayment);
            case 11:
                return LocaleController.getString(R.string.GroupOfIndividualsRedPacketPayment);
            case 12:
                return LocaleController.getString(R.string.RedPacketExpiredRefund);
            case 13:
                return LocaleController.getString(R.string.PlatformAccount);
            default:
                switch (i) {
                    case 19:
                        return LocaleController.getString(R.string.ScanCodeTransferCredit);
                    case 20:
                        return LocaleController.getString(R.string.ScanCodeTransferPayment);
                    case 21:
                        return LocaleController.getString(R.string.BackstageAccount);
                    case 22:
                        return LocaleController.getString(R.string.MerchantTransactionCollection);
                    case 23:
                        return LocaleController.getString(R.string.MerchantTransactionPayment);
                    case 24:
                        return LocaleController.getString(R.string.MerchantTransactionRefund);
                    case 25:
                        return LocaleController.getString(R.string.BackOfficeAccount);
                    default:
                        return LocaleController.getString(R.string.UnKnown);
                }
        }
    }

    public int getTypeIcon() {
        int i = this.orderType;
        if (i == 0) {
            int i2 = this.status;
            if (i2 == 0 || i2 == 1) {
                return R.id.ic_top_up_success;
            }
            return R.id.ic_top_up_failed;
        }
        if (i == 1) {
            return R.id.ic_trade_withdrawal;
        }
        if (i == 3) {
            return R.id.ic_transfer_refund;
        }
        if (i != 21) {
            switch (i) {
                case 5:
                case 6:
                case 7:
                    return R.id.ic_bill_detail_trasfer;
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                    return R.id.ic_bill_detail_packet;
                case 13:
                    return R.id.ic_back_top_up;
                default:
                    switch (i) {
                        case 25:
                            return R.id.ic_back_top_up;
                        case 26:
                        case 27:
                            return R.id.ic_order_live;
                        default:
                            return R.id.transfer_success_icon;
                    }
            }
        }
        return R.id.ic_back_top_up;
    }
}
