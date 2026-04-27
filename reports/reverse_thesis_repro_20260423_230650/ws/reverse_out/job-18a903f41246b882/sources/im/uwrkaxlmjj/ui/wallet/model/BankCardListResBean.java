package im.uwrkaxlmjj.ui.wallet.model;

import android.text.TextUtils;
import com.alibaba.fastjson.JSON;
import im.uwrkaxlmjj.messenger.FileLog;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public class BankCardListResBean implements Serializable {
    private String createTime;
    private int id;
    private String info;
    private Map<String, Object> infoMap;
    private String reactType;
    private int supportId;
    private int templateId;
    private int userId;

    public String getReactType() {
        return this.reactType;
    }

    public void setReactType(String reactType) {
        this.reactType = reactType;
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getCreateTime() {
        return this.createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public int getSupportId() {
        return this.supportId;
    }

    public void setSupportId(int supportId) {
        this.supportId = supportId;
    }

    public int getTemplateId() {
        return this.templateId;
    }

    public void setTemplateId(int templateId) {
        this.templateId = templateId;
    }

    public int getUserId() {
        return this.userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public String getInfo() {
        return this.info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public Map<String, Object> getInfoMap() {
        if (this.infoMap == null && !TextUtils.isEmpty(getInfo())) {
            try {
                this.infoMap = (Map) JSON.parseObject(getInfo(), LinkedHashMap.class);
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
}
