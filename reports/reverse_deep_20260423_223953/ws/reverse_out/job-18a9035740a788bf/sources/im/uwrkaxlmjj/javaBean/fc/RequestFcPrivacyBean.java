package im.uwrkaxlmjj.javaBean.fc;

import java.io.Serializable;

/* JADX INFO: loaded from: classes2.dex */
public class RequestFcPrivacyBean implements Serializable {
    private long IgnoreID;
    private long UserID;

    public RequestFcPrivacyBean(long userID, long ignoreID) {
        this.UserID = userID;
        this.IgnoreID = ignoreID;
    }

    public long getUserID() {
        return this.UserID;
    }

    public void setUserID(long userID) {
        this.UserID = userID;
    }

    public long getIgnoreID() {
        return this.IgnoreID;
    }

    public void setIgnoreID(long ignoreID) {
        this.IgnoreID = ignoreID;
    }
}
