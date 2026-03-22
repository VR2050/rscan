package com.jbzd.media.movecartoons.bean.response;

/* loaded from: classes2.dex */
public class UploadVideoResultResponse {
    private DataBean data;
    private String status;
    private String time;

    public static class DataBean {
        private String file;
        private String file_small;

        /* renamed from: id */
        private String f9991id;
        private int page;
        private int total_page;

        public String getFile() {
            return this.file;
        }

        public String getFile_small() {
            return this.file_small;
        }

        public String getId() {
            return this.f9991id;
        }

        public int getPage() {
            return this.page;
        }

        public int getTotal_page() {
            return this.total_page;
        }

        public void setFile(String str) {
            this.file = str;
        }

        public void setFile_small(String str) {
            this.file_small = str;
        }

        public void setId(String str) {
            this.f9991id = str;
        }

        public void setPage(int i2) {
            this.page = i2;
        }

        public void setTotal_page(int i2) {
            this.total_page = i2;
        }
    }

    public DataBean getData() {
        return this.data;
    }

    public String getStatus() {
        return this.status;
    }

    public String getTime() {
        return this.time;
    }

    public void setData(DataBean dataBean) {
        this.data = dataBean;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setTime(String str) {
        this.time = str;
    }
}
