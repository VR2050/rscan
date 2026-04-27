package im.uwrkaxlmjj.ui.wallet.model;

import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class BillRecordsResBean {
    private ArrayList<BillRecordResBillListBean> billList;
    private String dateTime;
    private BillRecordResStatisticsBean statistics;

    public String getDateTime() {
        return this.dateTime;
    }

    public void setDateTime(String dateTime) {
        this.dateTime = dateTime;
    }

    public ArrayList<BillRecordResBillListBean> getBillList() {
        return this.billList;
    }

    public void setBillList(ArrayList<BillRecordResBillListBean> billList) {
        this.billList = billList;
    }

    public BillRecordResStatisticsBean getStatistics() {
        return this.statistics;
    }

    public void setStatistics(BillRecordResStatisticsBean statistics) {
        this.statistics = statistics;
    }
}
