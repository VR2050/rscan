package im.uwrkaxlmjj.ui.hui.transfer.bean;

import android.text.TextUtils;
import androidx.exifinterface.media.ExifInterface;
import com.blankj.utilcode.util.TimeUtils;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class TransferResponse {
    private String cancelTime;
    private String collectTime;
    private String createTime;
    private String initiatorUserId;
    private String recipientUserId;
    private String remarks;
    private String serialCode;
    private String status;
    private String totalFee;

    public enum Status {
        NONE,
        WAITING,
        RECEIVED,
        CANCEL,
        REFUSED,
        TIMEOUT
    }

    public String getSerialCode() {
        return this.serialCode;
    }

    public String getTotalFee() {
        return this.totalFee;
    }

    public String getStatus() {
        return this.status;
    }

    public String getInitiatorUserId() {
        return this.initiatorUserId;
    }

    public String getRecipientUserId() {
        return this.recipientUserId;
    }

    public String getRemarks() {
        return this.remarks;
    }

    public String getCreateTime() {
        return this.createTime;
    }

    public String getCollectTime() {
        return this.collectTime;
    }

    public String getCancelTime() {
        return this.cancelTime;
    }

    public int getInitiatorUserIdInt() {
        if (NumberUtil.isNumber(this.initiatorUserId)) {
            return Integer.parseInt(this.initiatorUserId);
        }
        return -1;
    }

    public String getCollectTimeFormat() {
        String str = this.collectTime;
        if (str != null && TextUtils.isDigitsOnly(str) && !"0".equals(this.collectTime)) {
            return TimeUtils.millis2String(Long.parseLong(this.collectTime), LocaleController.getString("formatterStandard24H", R.string.formatterStandard24H));
        }
        return this.collectTime + "";
    }

    public String getCancelTimeFormat() {
        String str = this.cancelTime;
        if (str != null && TextUtils.isDigitsOnly(str) && !"0".equals(this.cancelTime)) {
            return TimeUtils.millis2String(Long.parseLong(this.cancelTime), LocaleController.getString("formatterStandard24H", R.string.formatterStandard24H));
        }
        if (this.cancelTime == null) {
            return "";
        }
        return this.cancelTime + "";
    }

    public String getCreateTimeFormat() {
        String str = this.createTime;
        if (str != null && TextUtils.isDigitsOnly(str) && !"0".equals(this.createTime)) {
            return TimeUtils.millis2String(Long.parseLong(this.createTime), LocaleController.getString("formatterStandard24H", R.string.formatterStandard24H));
        }
        if (this.createTime == null) {
            return "";
        }
        return this.createTime + "";
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public Status getState() {
        if (TextUtils.isEmpty(this.status)) {
            return Status.NONE;
        }
        String str = this.status;
        byte b = -1;
        switch (str.hashCode()) {
            case 49:
                if (str.equals("1")) {
                    b = 0;
                }
                break;
            case 50:
                if (str.equals("2")) {
                    b = 1;
                }
                break;
            case 51:
                if (str.equals(ExifInterface.GPS_MEASUREMENT_3D)) {
                    b = 2;
                }
                break;
            case 52:
                if (str.equals("4")) {
                    b = 3;
                }
                break;
            case 53:
                if (str.equals("5")) {
                    b = 4;
                }
                break;
        }
        if (b == 0) {
            return Status.WAITING;
        }
        if (b == 1) {
            return Status.RECEIVED;
        }
        if (b == 2) {
            return Status.CANCEL;
        }
        if (b == 3) {
            return Status.REFUSED;
        }
        if (b == 4) {
            return Status.TIMEOUT;
        }
        return Status.NONE;
    }
}
