package im.uwrkaxlmjj.ui.hui.packet.bean;

import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class RecordResponse {
    private ArrayList<RecordBean> record;
    private RecordsInfo redCount;

    public RecordsInfo getRedCount() {
        return this.redCount;
    }

    public void setRedCount(RecordsInfo redCount) {
        this.redCount = redCount;
    }

    public ArrayList<RecordBean> getRecord() {
        return this.record;
    }

    public void setRecord(ArrayList<RecordBean> record) {
        this.record = record;
    }
}
