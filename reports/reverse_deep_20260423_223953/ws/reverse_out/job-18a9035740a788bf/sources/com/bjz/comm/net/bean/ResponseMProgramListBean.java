package com.bjz.comm.net.bean;

import java.io.Serializable;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class ResponseMProgramListBean implements Serializable {
    private PageBean Page;
    private ArrayList<MiniProgramBean> Rows;

    public PageBean getPage() {
        return this.Page;
    }

    public void setPage(PageBean Page) {
        this.Page = Page;
    }

    public ArrayList<MiniProgramBean> getRows() {
        return this.Rows;
    }

    public void setRows(ArrayList<MiniProgramBean> Rows) {
        this.Rows = Rows;
    }

    public static class PageBean {
        private int CurrentPage;
        private int Limit;
        private int Offset;
        private String Order;
        private int PageCount;
        private int PageSize;
        private String Sort;
        private int TotalRows;

        public int getTotalRows() {
            return this.TotalRows;
        }

        public void setTotalRows(int TotalRows) {
            this.TotalRows = TotalRows;
        }

        public int getPageCount() {
            return this.PageCount;
        }

        public void setPageCount(int PageCount) {
            this.PageCount = PageCount;
        }

        public int getPageSize() {
            return this.PageSize;
        }

        public void setPageSize(int PageSize) {
            this.PageSize = PageSize;
        }

        public int getCurrentPage() {
            return this.CurrentPage;
        }

        public void setCurrentPage(int CurrentPage) {
            this.CurrentPage = CurrentPage;
        }

        public int getOffset() {
            return this.Offset;
        }

        public void setOffset(int Offset) {
            this.Offset = Offset;
        }

        public int getLimit() {
            return this.Limit;
        }

        public void setLimit(int Limit) {
            this.Limit = Limit;
        }

        public String getOrder() {
            return this.Order;
        }

        public void setOrder(String Order) {
            this.Order = Order;
        }

        public String getSort() {
            return this.Sort;
        }

        public void setSort(String Sort) {
            this.Sort = Sort;
        }
    }
}
