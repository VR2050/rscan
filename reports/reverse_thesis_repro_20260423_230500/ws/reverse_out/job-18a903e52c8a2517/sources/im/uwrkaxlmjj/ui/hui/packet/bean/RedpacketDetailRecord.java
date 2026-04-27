package im.uwrkaxlmjj.ui.hui.packet.bean;

import android.text.TextUtils;
import com.blankj.utilcode.util.TimeUtils;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpacketDetailRecord {
    private String createTime;
    private String isOptimum;
    private String totalFee;
    private String userId;

    public RedpacketDetailRecord(String createTime, String totalFee, String userId, String isOptimum) {
        this.createTime = createTime;
        this.totalFee = totalFee;
        this.userId = userId;
        this.isOptimum = isOptimum;
    }

    public String getIsOptimum() {
        return this.isOptimum;
    }

    public String getCreateTime() {
        return this.createTime;
    }

    public String getTotalFee() {
        return this.totalFee;
    }

    public String getUserId() {
        return this.userId;
    }

    public int getUserIdInt() {
        String str = this.userId;
        if (str != null && NumberUtil.isNumber(str)) {
            return Integer.parseInt(this.userId);
        }
        return 0;
    }

    public String getCreateTimeFormat() {
        String str = this.createTime;
        if (str != null && TextUtils.isDigitsOnly(str) && !"0".equals(this.createTime)) {
            return TimeUtils.millis2String(Long.parseLong(this.createTime), LocaleController.getString("formatterMonthDayTime24H", R.string.formatterMonthDayTime24H));
        }
        return this.createTime + "";
    }

    public long getCreatTimeLong() {
        String str = this.createTime;
        if (str != null && TextUtils.isDigitsOnly(str)) {
            return Long.parseLong(this.createTime);
        }
        return 0L;
    }
}
