package im.uwrkaxlmjj.ui.wallet.model;

import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class BillRecordsReqBean {
    private String businessKey;
    private String date;
    private ArrayList<Integer> orderTypes = new ArrayList<>();
    private int pageNum;
    private int pageSize;
    private int userId;

    public String getBusinessKey() {
        return this.businessKey;
    }

    public void setBusinessKey(String businessKey) {
        this.businessKey = businessKey;
    }

    public int getUserId() {
        return this.userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public String getDate() {
        return this.date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public ArrayList<Integer> getOrderTypes() {
        return this.orderTypes;
    }

    public void setOrderTypes(ArrayList<Integer> orderTypes) {
        this.orderTypes = orderTypes;
    }

    public int getPageNum() {
        return this.pageNum;
    }

    public void setPageNum(int pageNum) {
        this.pageNum = pageNum;
    }

    public int getPageSize() {
        return this.pageSize;
    }

    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }
}
