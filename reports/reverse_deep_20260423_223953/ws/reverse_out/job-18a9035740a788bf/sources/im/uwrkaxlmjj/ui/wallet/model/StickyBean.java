package im.uwrkaxlmjj.ui.wallet.model;

/* JADX INFO: loaded from: classes5.dex */
public class StickyBean {
    private BillRecordResBillListBean bean;
    private String dateTime;
    private BillRecordResStatisticsBean statistics;
    private int type;

    public StickyBean(String dateTime, BillRecordResStatisticsBean statistics, int type) {
        this.dateTime = dateTime;
        this.type = type;
        this.statistics = statistics;
    }

    public StickyBean(BillRecordResBillListBean bean, int type) {
        this.bean = bean;
        this.type = type;
    }

    public String getDateTime() {
        return this.dateTime;
    }

    public void setDateTime(String dateTime) {
        this.dateTime = dateTime;
    }

    public BillRecordResBillListBean getBean() {
        return this.bean;
    }

    public void setBean(BillRecordResBillListBean bean) {
        this.bean = bean;
    }

    public BillRecordResStatisticsBean getStatistics() {
        return this.statistics;
    }

    public void setStatistics(BillRecordResStatisticsBean statistics) {
        this.statistics = statistics;
    }

    public int getType() {
        return this.type;
    }
}
