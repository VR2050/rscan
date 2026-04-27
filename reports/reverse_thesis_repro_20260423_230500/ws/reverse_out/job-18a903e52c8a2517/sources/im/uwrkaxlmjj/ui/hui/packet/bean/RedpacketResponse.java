package im.uwrkaxlmjj.ui.hui.packet.bean;

import im.uwrkaxlmjj.messenger.UserConfig;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class RedpacketResponse {
    private ArrayList<RedpacketDetailRecord> records;
    private RedpacketBean red;
    private ArrayList<Integer> userList;
    private int statusRecv = -1;
    private int selfStatus = -1;

    public RedpacketBean getRed() {
        return this.red;
    }

    public void setRed(RedpacketBean red) {
        this.red = red;
    }

    public boolean isReceived() {
        ArrayList<RedpacketDetailRecord> arrayList;
        ArrayList<Integer> arrayList2 = this.userList;
        if ((arrayList2 == null || arrayList2.size() == 0) && ((arrayList = this.records) == null || arrayList.size() == 0)) {
            return false;
        }
        boolean finish = this.red.getStatusInt() == 1 || this.red.getStatusInt() == 2;
        if (finish) {
            int i = this.selfStatus;
            if (i == 1) {
                return true;
            }
            if (i == 0) {
                return false;
            }
        }
        ArrayList<Integer> arrayList3 = this.userList;
        if (arrayList3 != null && arrayList3.size() > 0) {
            for (Integer uid : this.userList) {
                if (uid.intValue() == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                    if (finish) {
                        this.selfStatus = 1;
                    }
                    return true;
                }
            }
        }
        ArrayList<RedpacketDetailRecord> arrayList4 = this.records;
        if (arrayList4 != null && arrayList4.size() > 0) {
            for (RedpacketDetailRecord record : this.records) {
                if (record.getUserIdInt() == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                    if (finish) {
                        this.selfStatus = 1;
                    }
                    return true;
                }
            }
        }
        if (finish) {
            this.selfStatus = 0;
        }
        return false;
    }
}
